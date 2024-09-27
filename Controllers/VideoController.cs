using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace VideoEncryptionAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class VideoController : ControllerBase
    {
        private const int BufferSize = 512 * 1024; // 64 KB
        private static readonly string EncryptedVideoPath = Path.Combine(Directory.GetCurrentDirectory(), "Videos/sampleV.mp4");
        private static readonly RSA rsa = RSA.Create(4096);

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
                    string aesKeyPath = Path.Combine(Directory.GetCurrentDirectory(), "Videos/aesKey.bin");
                    await System.IO.File.WriteAllBytesAsync(aesKeyPath, encryptedAesKey);

                    // Save the IV for later use
                    string aesIvPath = Path.Combine(Directory.GetCurrentDirectory(), "Videos/aesIv.bin");
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
                aes.KeySize = 256;
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
                return File(encryptedVideoData, "application/octet-stream", "Videos/encryptedVideo.mp4");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        [HttpGet("decrypt-and-save-video")]
        public async Task<IActionResult> DecryptAndSaveVideo()
        {
            if (!System.IO.File.Exists(EncryptedVideoPath))
                return NotFound("Encrypted video not found.");

            try
            {
                // Read encrypted AES key
                byte[] encryptedAesKey = await System.IO.File.ReadAllBytesAsync(Path.Combine(Directory.GetCurrentDirectory(), "Videos/aesKey.bin"));

                // Decrypt AES key using RSA
                byte[] aesKey = rsa.Decrypt(encryptedAesKey, RSAEncryptionPadding.OaepSHA256);

                // Read IV
                byte[] aesIV = await System.IO.File.ReadAllBytesAsync(Path.Combine(Directory.GetCurrentDirectory(), "Videos/aesIv.bin"));

                // Decrypt the video data
                byte[] encryptedVideoData = await System.IO.File.ReadAllBytesAsync(EncryptedVideoPath);
                byte[] decryptedVideoData = DecryptVideo(encryptedVideoData, aesKey, aesIV);

                // Save decrypted video to a new file
                var decryptedVideoPath = Path.Combine(Directory.GetCurrentDirectory(), "Videos/decryptedVideo.mp4");
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

                using (var cryptoStream = new CryptoStream(new MemoryStream(encryptedData), aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    cryptoStream.CopyTo(memoryStream);
                }

                return memoryStream.ToArray();
            }
        }

        // Endpoint for streaming decrypted video without Range
        [HttpGet("stream-decrypted-video-safe")]
        public async Task<IActionResult> StreamDecryptedVideo()
        {
            if (!System.IO.File.Exists(EncryptedVideoPath))
                return NotFound("Encrypted video not found.");

            try
            {
                // Read encrypted AES key
                byte[] encryptedAesKey = await System.IO.File.ReadAllBytesAsync(Path.Combine(Directory.GetCurrentDirectory(), "Videos/aesKey.bin"));
                byte[] aesKey = rsa.Decrypt(encryptedAesKey, RSAEncryptionPadding.OaepSHA256);
                byte[] aesIV = await System.IO.File.ReadAllBytesAsync(Path.Combine(Directory.GetCurrentDirectory(), "Videos/aesIv.bin"));

                // Read encrypted video data
                byte[] encryptedVideoData = await System.IO.File.ReadAllBytesAsync(EncryptedVideoPath);
                byte[] decryptedVideoData = DecryptVideo(encryptedVideoData, aesKey, aesIV);

                // Stream the decrypted video to the client
                return File(decryptedVideoData, "video/mp4");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }


        [HttpGet("stream-decrypted-video-seek")]
        public async Task<IActionResult> StreamDecryptedVideoSeek(long? start, long? end)
        {
            if (!System.IO.File.Exists(EncryptedVideoPath))
                return NotFound("Encrypted video not found.");

            try
            {
                byte[] encryptedAesKey = await System.IO.File.ReadAllBytesAsync(Path.Combine(Directory.GetCurrentDirectory(), "Videos/aesKey.bin"));
                byte[] aesKey = rsa.Decrypt(encryptedAesKey, RSAEncryptionPadding.OaepSHA256);
                byte[] aesIV = await System.IO.File.ReadAllBytesAsync(Path.Combine(Directory.GetCurrentDirectory(), "Videos/aesIv.bin"));

                // Read and decrypt the video data
                byte[] encryptedVideoData = await System.IO.File.ReadAllBytesAsync(EncryptedVideoPath);
                byte[] decryptedVideoData = DecryptVideo(encryptedVideoData, aesKey, aesIV);

                // Set the range for streaming
                long contentLength = decryptedVideoData.Length;
                start ??= 0; // Start from 0 if not specified
                end ??= contentLength - 1; // End at the last byte if not specified

                // Validate the range
                if (start < 0 || end >= contentLength || start > end)
                    return BadRequest("Invalid range specified.");

                // Create a stream for the specific range
                var rangeLength = end.Value - start.Value + 1;
                var resultStream = new MemoryStream(decryptedVideoData, (int)start.Value, (int)rangeLength);

                Response.Headers.Add("Content-Range", $"bytes {start}-{end}/{contentLength}");
                Response.StatusCode = StatusCodes.Status206PartialContent; // 206 Partial Content

                return File(resultStream, "video/mp4", enableRangeProcessing: true);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

    }
}
