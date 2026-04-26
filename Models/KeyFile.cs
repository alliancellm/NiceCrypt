using System;
using System.Text.Json.Serialization;

namespace NiceCrypt.Models
{
    public class KeyFile
    {
        [JsonPropertyName("algorithm")]
        public string Algorithm { get; set; } = "AES-256-GCM";

        [JsonPropertyName("key")]
        public string Key { get; set; } = string.Empty;

        [JsonPropertyName("created")]
        public DateTime Created { get; set; }
    }
}
