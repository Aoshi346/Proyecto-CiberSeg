# CiberSeg Antivirus Module

This module provides antivirus functionality using the VirusTotal API for comprehensive malware detection.

## Setup Instructions

### 1. Get VirusTotal API Key

1. Go to [VirusTotal](https://www.virustotal.com/)
2. Create a free account
3. Go to your profile settings
4. Generate an API key

### 2. Configure API Key

You have two options to configure your API key:

#### Option A: Environment Variable (Recommended)
```bash
# Windows
set VIRUSTOTAL_API_KEY=ab84f5f3146a5c18429112267f85a1007d64756dd1940efedaf7d2cf6466ca47

# Linux/Mac
export VIRUSTOTAL_API_KEY=your_api_key_here
```

#### Option B: Configuration File
1. Copy `config.py.example` to `config.py`
2. Replace `ab84f5f3146a5c18429112267f85a1007d64756dd1940efedaf7d2cf6466ca47` with your actual API key

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## Usage

### Command Line Usage

```bash
# Scan a specific file
python antivirus.py scan-file --file "path/to/file.exe"

# Scan a directory
python antivirus.py scan --directory "path/to/directory"

# Quick system scan (common directories)
python antivirus.py scan --scan-type quick

# Get antivirus status
python antivirus.py status

# Get scan statistics
python antivirus.py stats

# Update database (placeholder)
python antivirus.py update-db
```

### API Integration

The module is designed to work with the Electron main process through JSON output.

## Features

- **File Hash Scanning**: Fast scanning using SHA256 hashes
- **File Upload Scanning**: Upload files for comprehensive analysis
- **Directory Scanning**: Scan entire directories recursively
- **Real-time Results**: Get immediate scan results
- **Threat Detection**: Identify malware using 70+ antivirus engines
- **Statistics Tracking**: Track scan history and statistics

## API Limits

- **Free Tier**: 4 requests per minute, 500 requests per day
- **File Size Limit**: 32MB maximum file size
- **Rate Limiting**: Built-in delays to respect API limits

## Error Handling

The module includes comprehensive error handling for:
- Network connectivity issues
- API rate limiting
- File access errors
- Invalid API keys
- Large file uploads

## Security Notes

- API keys are stored securely
- File uploads are temporary and deleted after scanning
- No sensitive data is logged
- All communications use HTTPS

## Troubleshooting

### Common Issues

1. **"No VirusTotal API key provided"**
   - Ensure your API key is set correctly
   - Check environment variables or config file

2. **"File too large"**
   - VirusTotal has a 32MB file size limit
   - Compress or split large files

3. **"API rate limit exceeded"**
   - Wait a few minutes before retrying
   - Consider upgrading to a paid VirusTotal plan

4. **"Scan timeout"**
   - Large files may take longer to scan
   - Check your internet connection

### Debug Mode

Enable debug logging by setting the log level:
```python
logging.basicConfig(level=logging.DEBUG)
```
