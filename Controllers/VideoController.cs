using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace VideoEncryptionAPI.Controllers;

[ApiController]
[Route("api/[controller]")]
public class VideoController : ControllerBase
{
    private const int BufferSize = 64 * 1024; // 64 KB

    private static readonly string EncryptedVideoPath = Path.Combine(Directory.GetCurrentDirectory(), "sampleV.mp4");


    private static readonly RSA rsa = RSA.Create();

    // Endpoint for uploading and encrypting the video
    [HttpPost("upload")]
    public async Task<IActionResult> UploadVideo(IFormFile file)
    {
        if (file == null || file.Length == 0)
            return BadRequest("Invalid video file.");

        try
        {
            // Generate AES key
            using (var aes = Aes.Create())
            {
                aes.GenerateKey();
                aes.GenerateIV();

                // Encrypt the video data
                byte[] encryptedData = await EncryptVideo(file, aes.Key, aes.IV);

                // Encrypt the AES key with RSA
                byte[] encryptedAesKey = rsa.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256);

                // Save encrypted AES key and IV to a secure location (e.g., database)
                // Here we will just save it to a file for demonstration
                string aesKeyPath = Path.Combine(Directory.GetCurrentDirectory(), "aesKey.bin");
                await System.IO.File.WriteAllBytesAsync(aesKeyPath, encryptedAesKey);

                // Save the IV for later use
                string aesIvPath = Path.Combine(Directory.GetCurrentDirectory(), "aesIv.bin");
                await System.IO.File.WriteAllBytesAsync(aesIvPath, aes.IV);

                // Save the encrypted video
                await System.IO.File.WriteAllBytesAsync(EncryptedVideoPath, encryptedData);
            }

            return Ok("Video uploaded and encrypted successfully.");
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"Internal server error: {ex.Message}");
        }
    }

    private async Task<byte[]> EncryptVideo(IFormFile file, byte[] aesKey, byte[] aesIV)
    {
        using (var memoryStream = new MemoryStream())
        using (var aes = Aes.Create())
        {
            aes.Key = aesKey;
            aes.IV = aesIV;

            using (var cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                await file.CopyToAsync(cryptoStream);
            }

            return memoryStream.ToArray();
        }
    }

    // Endpoint for downloading
    [HttpGet("download")]
    public async Task<IActionResult> DownloadVideo()
    {
        if (!System.IO.File.Exists(EncryptedVideoPath))
            return NotFound("Encrypted video not found.");

        try
        {
            byte[] encryptedVideoData = await System.IO.File.ReadAllBytesAsync(EncryptedVideoPath);
            return File(encryptedVideoData, "application/octet-stream", "encryptedVideo.mp4");
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"Internal server error: {ex.Message}");
        }
    }



    [HttpGet("decrypt-and-save")]
    public async Task<IActionResult> DecryptAndSaveVideo()
    {
        if (!System.IO.File.Exists(EncryptedVideoPath))
            return NotFound("Encrypted video not found.");

        try
        {
            // Read encrypted AES key
            byte[] encryptedAesKey = await System.IO.File.ReadAllBytesAsync(Path.Combine(Directory.GetCurrentDirectory(), "aesKey.bin"));

            // Decrypt AES key using RSA
            byte[] aesKey = rsa.Decrypt(encryptedAesKey, RSAEncryptionPadding.OaepSHA256);

            // Read IV
            byte[] aesIV = await System.IO.File.ReadAllBytesAsync(Path.Combine(Directory.GetCurrentDirectory(), "aesIv.bin"));

            // Decrypt the video data
            byte[] encryptedVideoData = await System.IO.File.ReadAllBytesAsync(EncryptedVideoPath);
            byte[] decryptedVideoData = DecryptVideo(encryptedVideoData, aesKey, aesIV);

            // Save decrypted video to a new file
            var decryptedVideoPath = Path.Combine(Directory.GetCurrentDirectory(), "decryptedVideo.mp4");
            await System.IO.File.WriteAllBytesAsync(decryptedVideoPath, decryptedVideoData);

            return Ok($"Video decrypted and saved successfully at: {decryptedVideoPath}");
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"Internal server error: {ex.Message}");
        }
    }

    // Endpoint to stream encrypted video chunks to the client
    // Method to encrypt the AES key using RSA
    private byte[] EncryptAesKeyWithRsa(byte[] aesKey)
    {
        using var rsa = RSA.Create();
        // Load your RSA public key here (assuming you have a method to load it)
        // rsa.ImportRSAPublicKey(yourPublicKeyBytes, out _);

        return rsa.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);
    }
    
    private byte[] DecryptAesKeyWithRsa(byte[] rsaEncryptedKey)
    {
        string privateKeyFilePath = Path.Combine(Directory.GetCurrentDirectory(), "privateKey.xml");
        using var rsa = RSA.Create();

        if (!File.Exists(privateKeyFilePath))
        {
            using (var rsaNew = new RSACryptoServiceProvider(2048))
            {
                string privateKeyXml = rsaNew.ToXmlString(true);
                File.WriteAllText(privateKeyFilePath, privateKeyXml);
            }
        }

        string privateKeyXmlFromFile = File.ReadAllText(privateKeyFilePath);
        rsa.FromXmlString(privateKeyXmlFromFile);

        byte[] aesKey = rsa.Decrypt(rsaEncryptedKey, RSAEncryptionPadding.OaepSHA256);
        return aesKey;
    }



    [HttpGet("stream-encrypted-video-performance")]
    public async Task<IActionResult> StreamEncryptedVideoPerformance()
    {
        if (!System.IO.File.Exists(EncryptedVideoPath))
            return NotFound("Video file not found.");

        try
        {
            // 1. Generate AES key and IV
            using var aes = Aes.Create();
            aes.GenerateKey();
            aes.GenerateIV();

            // 2. Encrypt AES key with RSA (assuming RSA is already generated and stored)
            byte[] rsaEncryptedKey = EncryptAesKeyWithRsa(aes.Key);

            // 3. Stream the RSA encrypted AES key to the client (for example purposes)
            Response.ContentType = "application/octet-stream";
            await Response.Body.WriteAsync(rsaEncryptedKey, 0, rsaEncryptedKey.Length);
            await Response.Body.WriteAsync(new byte[] { 0 }, 0, 1); // Separator

            // 4. Stream the encrypted video
            using (var fileStream = new FileStream(EncryptedVideoPath, FileMode.Open, FileAccess.Read))
            using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
            using (var cryptoStream = new CryptoStream(Response.Body, encryptor, CryptoStreamMode.Write))
            {
                await fileStream.CopyToAsync(cryptoStream);
            }

            return new EmptyResult();
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"Internal server error: {ex.Message}");
        }
    }

    [HttpGet("stream-encrypted-video-tested")]
    public async Task<IActionResult> StreamEncryptedVideoTested()
    {
        if (!System.IO.File.Exists(EncryptedVideoPath))
            return NotFound("Video file not found.");

        try
        {
            // 1. Generate AES key and IV
            using var aes = Aes.Create();
            aes.GenerateKey();
            aes.GenerateIV();

            // 2. Encrypt AES key with RSA
            byte[] rsaEncryptedKey = EncryptAesKeyWithRsa(aes.Key);

            // 3. Stream the RSA encrypted AES key to the client
            Response.ContentType = "application/octet-stream";
            await Response.Body.WriteAsync(rsaEncryptedKey, 0, rsaEncryptedKey.Length);
            await Response.Body.WriteAsync(new byte[] { 0 }, 0, 1); // Separator

            // 4. Stream the encrypted video
            using (var fileStream = new FileStream(EncryptedVideoPath, FileMode.Open, FileAccess.Read))
            using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
            using (var cryptoStream = new CryptoStream(Response.Body, encryptor, CryptoStreamMode.Write))
            {
                await fileStream.CopyToAsync(cryptoStream);
            }

            return new EmptyResult();
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"Internal server error: {ex.Message}");
        }
    }



    [HttpGet("stream-decrypted-video-seek")]
    public async Task<IActionResult> StreamDecryptedVideo()
    {
        if (!System.IO.File.Exists(EncryptedVideoPath))
            return NotFound("Encrypted video not found.");

        try
        {
            byte[] encryptedVideoData = System.IO.File.ReadAllBytes(EncryptedVideoPath);

            // Decrypt the AES key from RSA
            byte[] aesKey = DecryptAesKeyWithRsa(); // Implement this method to decrypt the key

            using var aes = Aes.Create();
            aes.Key = aesKey;
            aes.IV = /* Set your IV here, it should be sent along with the encrypted key */;

            // Decrypt the video data
            using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using var decryptedStream = new MemoryStream();

            using (var cryptoStream = new CryptoStream(decryptedStream, decryptor, CryptoStreamMode.Write))
            {
                await cryptoStream.WriteAsync(encryptedVideoData, 0, encryptedVideoData.Length);
            }

            // Streaming the decrypted video
            decryptedStream.Position = 0; // Reset position
            return File(decryptedStream.ToArray(), "video/mp4");
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"Internal server error: {ex.Message}");
        }
    }


    [HttpGet("stream-decrypted-video-not-seek")]
    public async Task<IActionResult> StreamDecryptedVideoNotSeek()
    {
        if (!System.IO.File.Exists(EncryptedVideoPath))
            return NotFound("Encrypted video not found.");

        try
        {
            byte[] encryptedVideoData = System.IO.File.ReadAllBytes(EncryptedVideoPath);

            // Decrypt the AES key from RSA
            byte[] aesKey = DecryptAesKeyWithRsa(); // Implement this method to decrypt the key

            using var aes = Aes.Create();
            aes.Key = aesKey;
            aes.IV = /* Set your IV here, it should be sent along with the encrypted key */;

            // Decrypt the video data
            using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using var decryptedStream = new MemoryStream();

            using (var cryptoStream = new CryptoStream(decryptedStream, decryptor, CryptoStreamMode.Write))
            {
                await cryptoStream.WriteAsync(encryptedVideoData, 0, encryptedVideoData.Length);
            }

            // Stream the decrypted video directly
            decryptedStream.Position = 0; // Reset position
            Response.ContentType = "video/mp4";
            return File(decryptedStream.ToArray(), "video/mp4");
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"Internal server error: {ex.Message}");
        }
    }



    [HttpGet("decrypt-and-saveede")]
    public async Task<IActionResult> DecryptAndSaveVideodd()
    {
        if (!System.IO.File.Exists(EncryptedVideoPath))
            return NotFound("Encrypted video not found.");

        try
        {
            // Read encrypted AES key
            byte[] encryptedAesKey = await System.IO.File.ReadAllBytesAsync(Path.Combine(Directory.GetCurrentDirectory(), "aesKey.bin"));

            // Decrypt AES key using RSA
            byte[] aesKey = rsa.Decrypt(encryptedAesKey, RSAEncryptionPadding.OaepSHA256);

            // Read IV
            byte[] aesIV = await System.IO.File.ReadAllBytesAsync(Path.Combine(Directory.GetCurrentDirectory(), "aesIv.bin"));

            // Decrypt the video data
            byte[] encryptedVideoData = await System.IO.File.ReadAllBytesAsync(EncryptedVideoPath);
            byte[] decryptedVideoData = DecryptVideo(encryptedVideoData, aesKey, aesIV);

            // Save decrypted video to a new file
            var decryptedVideoPath = Path.Combine(Directory.GetCurrentDirectory(), "decryptedVideo.mp4");
            await System.IO.File.WriteAllBytesAsync(decryptedVideoPath, decryptedVideoData);

            return Ok($"Video decrypted and saved successfully at: {decryptedVideoPath}");
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"Internal server error: {ex.Message}");
        }
    }

    private byte[] DecryptVideo(byte[] encryptedData, byte[] aesKey, byte[] aesIV)
    {
        using (var memoryStream = new MemoryStream())
        using (var aes = Aes.Create())
        {
            aes.Key = aesKey;
            aes.IV = aesIV;

            using (var cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
            {
                cryptoStream.Write(encryptedData, 0, encryptedData.Length);
                cryptoStream.FlushFinalBlock();
            }

            return memoryStream.ToArray();
        }
    }


}