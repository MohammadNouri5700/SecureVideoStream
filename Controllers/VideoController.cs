using System;
using System.IO;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Threading.Tasks;
using Org.BouncyCastle.Security;

public class VideoController : ControllerBase
{
    private readonly ILogger<VideoController> _logger;
    private byte[] nonce = new byte[12];  
    public VideoController(ILogger<VideoController> logger)
    {
        RandomNumberGenerator.Fill(nonce);
        _logger = logger;
    }

    


    [HttpGet("segment/{**videoDirectory}")]
    public async Task<IActionResult> GetHLSSegmentAsync(string videoDirectory)
    {
        if (videoDirectory.Contains("..") || Path.IsPathRooted(videoDirectory))
        {
            return BadRequest("Invalid directory.");
        }
        // string segmentName = Path.GetFileName(videoDirectory);
        string segmentPath = Path.Combine(videoDirectory);
        if (!System.IO.File.Exists(segmentPath))
        {
            return NotFound("Segment not found.");
        }

        //   Nonce
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
    
        // hmhm  test 
        var keyGenerator = new CipherKeyGenerator();
        keyGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 256));
        byte[] keyBytes = keyGenerator.GenerateKey();

        // Construct Nonce Data using Span<T> to avoid allocations
        byte[] data = new byte[keyBytes.Length + nonce.Length];
        nonce.AsSpan(6).CopyTo(data);
        keyBytes.AsSpan().CopyTo(data.AsSpan(6));
        nonce.AsSpan(0, 6).CopyTo(data.AsSpan(6 + keyBytes.Length));

        Response.Headers.Add("X-Nonce", Convert.ToBase64String(data));

        var parameters = new ParametersWithIV(new KeyParameter(keyBytes), nonce);
        var cipher = new ChaCha7539Engine();
        cipher.Init(true, parameters);

        Response.ContentType = "video/MP2T";

        const int BufferSize = 8192; 
        byte[] buffer = GC.AllocateUninitializedArray<byte>(BufferSize); // Avoid zeroing memory
        byte[] encryptedBuffer = GC.AllocateUninitializedArray<byte>(BufferSize);

        using var fileStream = new FileStream(segmentPath, FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize, FileOptions.Asynchronous | FileOptions.SequentialScan);
        int bytesRead;

        while ((bytesRead = await fileStream.ReadAsync(buffer.AsMemory(0, BufferSize))) > 0)
        {
            cipher.ProcessBytes(buffer, 0, bytesRead, encryptedBuffer, 0);
            await Response.Body.WriteAsync(encryptedBuffer.AsMemory(0, bytesRead));
        }

        return new EmptyResult();
    }


    
    
    // private byte[] EncryptData(byte[] buffer, int bytesRead, byte[] nonce)
    // {
    //     if (_key.Length > 32)
    //     {
    //         Array.Resize(ref _key, 32);
    //     }
    //
    //     var parameters = new ParametersWithIV(new KeyParameter(_key), nonce);
    //     cipher.Init(true, parameters);
    //
    //     byte[] encryptedData = new byte[bytesRead];
    //     cipher.ProcessBytes(buffer, 0, bytesRead, encryptedData, 0);
    //
    //     return encryptedData;  
    // }
}
