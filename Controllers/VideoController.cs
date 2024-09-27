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

    private static readonly byte[] AesKey = Encoding.UTF8.GetBytes("0123456789ABCDEF0123456789ABCDEF"); // 256-bit key
    private static readonly byte[] AesIV = Encoding.UTF8.GetBytes("0123456789ABCDEF"); // 128-bit IV
    private static readonly string EncryptedVideoPath = Path.Combine(Directory.GetCurrentDirectory(), "sampleV.mp4");

    // Endpoint for uploading and encrypting the video
    [HttpPost("upload")]
    public async Task<IActionResult> UploadVideo(IFormFile file)
    {
        if (file == null || file.Length == 0)
            return BadRequest("Invalid video file.");

        try
        {
            using (var memoryStream = new MemoryStream())
            {
                await file.CopyToAsync(memoryStream);
                byte[] videoData = memoryStream.ToArray();
                byte[] encryptedData = EncryptData(videoData);
                await System.IO.File.WriteAllBytesAsync(EncryptedVideoPath, encryptedData);
            }

            return Ok("Video uploaded and encrypted successfully.");
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"Internal server error: {ex.Message}");
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
    public IActionResult DecryptAndSaveVideo()
    {
        if (!System.IO.File.Exists(EncryptedVideoPath))
            return NotFound("Encrypted video not found.");

        try
        {
            // Read encrypted video data from file
            byte[] encryptedVideoData = System.IO.File.ReadAllBytes(EncryptedVideoPath);

            // Decrypt the video data
            byte[] decryptedVideoData = DecryptData(encryptedVideoData);

            // Save decrypted video to a new file
            var decryptedVideoPath = Path.Combine(Directory.GetCurrentDirectory(), "decryptedVideo.mp4");
            System.IO.File.WriteAllBytes(decryptedVideoPath, decryptedVideoData);

            return Ok($"Video decrypted and saved successfully at: {decryptedVideoPath}");
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"Internal server error: {ex.Message}");
        }
    }
    // Endpoint to stream encrypted video chunks to the client


    [HttpGet("stream-encrypted-video-performance")]
    public async Task<IActionResult> StreamEncryptedVideoPerformance()
    {
        if (!System.IO.File.Exists(EncryptedVideoPath))
            return NotFound("Video file not found.");

        try
        {
            using (var fileStream = new FileStream(EncryptedVideoPath, FileMode.Open, FileAccess.Read))
            using (var aesAlg = Aes.Create())
            {
                aesAlg.Key = AesKey;
                aesAlg.IV = AesIV;

                using (var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))
                using (var cryptoStream = new CryptoStream(Response.Body, encryptor, CryptoStreamMode.Write))
                {
                    Response.ContentType = "application/octet-stream";
                    await fileStream.CopyToAsync(cryptoStream);
                }
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
            const int bufferSize = 64 * 1024; // 64 KB buffer size
            byte[] buffer = new byte[bufferSize];

            // Open the video file for reading
            using (var fileStream = new FileStream(EncryptedVideoPath, FileMode.Open, FileAccess.Read))
            {
                using (var aesAlg = Aes.Create())
                {
                    aesAlg.Key = AesKey;
                    aesAlg.IV = AesIV;

                    using (var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))
                    {
                        using (var cryptoStream = new CryptoStream(Response.Body, encryptor, CryptoStreamMode.Write))
                        {
                            Response.ContentType = "application/octet-stream"; // Content type for encrypted data
                            int bytesRead;
                            while ((bytesRead = await fileStream.ReadAsync(buffer, 0, bufferSize)) > 0)
                            {
                                // Write encrypted data to the client
                                await cryptoStream.WriteAsync(buffer, 0, bytesRead);
                                await cryptoStream.FlushAsync(); // Ensure the chunk is sent immediately
                            }
                        }
                    }
                }
            }

            return new EmptyResult(); // End the response
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
            byte[] decryptedVideoData = DecryptData(encryptedVideoData);
            long videoLength = decryptedVideoData.Length; // Get the length of decrypted video
            Console.WriteLine($"Decrypted video length: {videoLength}"); // Log length

            var rangeHeader = Request.Headers["Range"].ToString();
            long start = 0, end = 0;

            // Check if Range header is provided
            if (string.IsNullOrEmpty(rangeHeader))
            {
                return File(decryptedVideoData, "video/mp4"); // Return full video if no range
            }

            // Parse the range
            var range = rangeHeader.Replace("bytes=", "").Split('-');
            if (long.TryParse(range[0], out start))
            {
                end = range.Length > 1 && long.TryParse(range[1], out long parsedEnd) ? parsedEnd : videoLength - 1;
            }
            else
            {
                return StatusCode(StatusCodes.Status416RangeNotSatisfiable);
            }

            // Log parsed range
            Console.WriteLine($"Range start: {start}, end: {end}, videoLength: {videoLength}");

            // Validate the range
            if (start < 0 || end < 0 || start >= videoLength || end >= videoLength || start > end)
            {
                return StatusCode(StatusCodes.Status416RangeNotSatisfiable);
            }

            long length = end - start + 1; // Calculate length of requested range
            Response.StatusCode = StatusCodes.Status206PartialContent; // Set status code to 206
            Response.ContentType = "video/mp4"; // Set content type to video/mp4
            Response.Headers.Add("Content-Range", $"bytes {start}-{end}/{videoLength}"); // Add content range header
            Response.Headers.Add("Accept-Ranges", "bytes"); // Indicate server accepts range requests
            Response.ContentLength = length; // Set content length to requested range length

            // Prepare to stream the requested range
            byte[] videoChunk = new byte[length]; // Create byte array for video chunk
            Array.Copy(decryptedVideoData, start, videoChunk, 0, length); // Copy requested range into video chunk

            using (var stream = new MemoryStream(videoChunk))
            {
                await stream.CopyToAsync(Response.Body); // Stream the video chunk to the response body
            }

            return new EmptyResult(); // End the response
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"Internal server error: {ex.Message}"); // Return 500 error in case of exception
        }
    }



    [HttpGet("stream-decrypted-video-not-seek")]
    public async Task<IActionResult> StreamDecryptedVideoNotSeek()
    {
        if (!System.IO.File.Exists(EncryptedVideoPath))
            return NotFound("Encrypted video not found.");

        try
        {
            // Set the response content type to video format (e.g., video/mp4)
            Response.ContentType = "video/mp4";

            // Read encrypted video data from file
            byte[] encryptedVideoData = System.IO.File.ReadAllBytes(EncryptedVideoPath);

            // Decrypt the video data
            byte[] decryptedVideoData = DecryptData(encryptedVideoData);

            // Define chunk size for streaming
            const int chunkSize = 1 * 1024 * 1024; // 1 MB


            // Start streaming the decrypted video in chunks
            using (var memoryStream = new MemoryStream(decryptedVideoData))
            {
                byte[] buffer = new byte[chunkSize];
                int bytesRead;
                while ((bytesRead = await memoryStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    await Response.Body.WriteAsync(buffer, 0, bytesRead);
                    await Response.Body.FlushAsync(); // Ensure the chunk is sent immediately
                }
            }

            return new EmptyResult(); // End the response
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"Internal server error: {ex.Message}");
        }
    }

    private byte[] DecryptData(byte[] encryptedData)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = AesKey;
            aesAlg.IV = AesIV;

            using (var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
            {
                using (var msDecrypt = new MemoryStream(encryptedData))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var msPlain = new MemoryStream())
                        {
                            csDecrypt.CopyTo(msPlain);
                            return msPlain.ToArray();
                        }
                    }
                }
            }
        }
    }
    private byte[] EncryptData(byte[] data, int length)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = AesKey;
            aesAlg.IV = AesIV;

            using (var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))
            {
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(data, 0, length);
                        csEncrypt.FlushFinalBlock();
                    }
                    return msEncrypt.ToArray();
                }
            }
        }
    }
    private byte[] EncryptData(byte[] data)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = AesKey;
            aesAlg.IV = AesIV;

            using (var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))
            {
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(data, 0, data.Length);
                        csEncrypt.FlushFinalBlock();
                    }
                    return msEncrypt.ToArray();
                }
            }
        }
    }
}