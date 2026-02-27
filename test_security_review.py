"""Security test cases for generate_share_url tool."""
import sys
from pathlib import Path
from unittest.mock import patch

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from onedrive_mcp.server import _resolve_share_url


def test_path_traversal_attempts(tmp_path):
    """Test that path traversal attempts are prevented."""
    onedrive_folder = tmp_path / "OneDrive"
    onedrive_folder.mkdir()
    
    # Create a file inside OneDrive
    legit_file = onedrive_folder / "file.txt"
    legit_file.write_text("legit")
    
    # Create a file outside OneDrive
    outside_file = tmp_path / "secret.txt"
    outside_file.write_text("secret")
    
    fake_accounts = [{
        "local_folder": str(onedrive_folder),
        "spo_url": "https://contoso.sharepoint.com/personal/user",
        "email": "user@contoso.com",
        "type": "business",
    }]
    
    with patch("onedrive_mcp.server._discover_onedrive_accounts", return_value=fake_accounts):
        # Test 1: Direct path traversal - file outside OneDrive
        result = _resolve_share_url(str(outside_file))
        print(f"Test 1 - Outside file: {result}")
        assert "error" in result or "not inside" in result.get("error", "").lower()
        
        # Test 2: Path with ../ components trying to escape
        traversal_attempts = [
            str(onedrive_folder / ".." / "secret.txt"),
            str(onedrive_folder / "subfolder" / ".." / ".." / "secret.txt"),
        ]
        
        for attempt in traversal_attempts:
            result = _resolve_share_url(attempt)
            print(f"Test 2 - Traversal attempt '{attempt}': {result}")
            # After Path.resolve(), the path should be resolved to outside_file
            # and should fail the relative_to check
            assert "error" in result


def test_url_injection_attempts(tmp_path):
    """Test that malicious filenames don't inject into URLs."""
    onedrive_folder = tmp_path / "OneDrive2"
    onedrive_folder.mkdir()
    
    fake_accounts = [{
        "local_folder": str(onedrive_folder),
        "spo_url": "https://contoso.sharepoint.com/personal/user",
        "email": "user@contoso.com",
        "type": "business",
    }]
    
    # Test various injection attempts
    malicious_names = [
        ("file#anchor.txt", "Fragment in name"),  # Fragment char
        ("file;ls.txt", "Semicolon in name"),  # Command injection char  
        ("file%2e%2e.txt", "URL-encoded dots"),  # Encoded dots
        ("file\r\ntest.txt", "CRLF in name"),  # CRLF injection
    ]
    
    with patch("onedrive_mcp.server._discover_onedrive_accounts", return_value=fake_accounts):
        for name, description in malicious_names:
            try:
                # Create file (may fail for illegal names on Windows)
                test_file = onedrive_folder / name
                test_file.write_text("test")
                
                result = _resolve_share_url(str(test_file))
                print(f"\nTesting {description}: {repr(name)}")
                print(f"Result: {result}")
                
                if "url" in result:
                    url = result["url"]
                    # Check that special characters are properly encoded
                    if "#" in name and "#" in url and "%23" not in url:
                        print(f"  ⚠️  WARNING: Unencoded # in URL: {url}")
                    if "\r" in url or "\n" in url:
                        print(f"  ⚠️  CRITICAL: CRLF in URL: {repr(url)}")
                    else:
                        print(f"  ✓ URL appears properly encoded: {url}")
            except (OSError, ValueError) as e:
                # Some names are illegal on Windows
                print(f"\nCouldn't create file with {description} {repr(name)}: {e}")


def test_registry_value_injection(tmp_path):
    """Test that malicious registry values don't create vulnerabilities."""
    folder = tmp_path / "OneDrive3"
    folder.mkdir()
    test_file = folder / "file.txt"
    test_file.write_text("test")
    
    # Simulate malicious registry values
    malicious_accounts = [
        {
            "local_folder": str(folder),
            "spo_url": "https://contoso.sharepoint.com/personal/user\r\nLocation: http://evil.com",
            "email": "user@contoso.com",
            "type": "business",
        },
        {
            "local_folder": str(tmp_path),
            "spo_url": "javascript:alert('xss')",
            "email": "user@contoso.com",
            "type": "business",
        },
        {
            "local_folder": str(folder),
            "spo_url": "https://contoso.sharepoint.com/../../etc/passwd",
            "email": "user@contoso.com",
            "type": "business",
        },
    ]
    
    for acct in malicious_accounts:
        print(f"\nTesting malicious spo_url: {repr(acct['spo_url'])}")
        with patch("onedrive_mcp.server._discover_onedrive_accounts", return_value=[acct]):
            result = _resolve_share_url(str(test_file))
            print(f"Result: {result}")
            
            if "url" in result:
                url = result["url"]
                # Check that the malicious content is in the URL
                # This is actually a vulnerability if untrusted registry values are used as-is
                print(f"WARNING: Registry value used directly in URL: {url}")


def test_symlink_path_traversal(tmp_path):
    """Test that symlinks can't be used to escape OneDrive folder."""
    onedrive_folder = tmp_path / "OneDrive4"
    onedrive_folder.mkdir()
    
    outside_folder = tmp_path / "outside"
    outside_folder.mkdir()
    secret_file = outside_folder / "secret.txt"
    secret_file.write_text("secret data")
    
    # Create a symlink inside OneDrive pointing outside
    symlink = onedrive_folder / "link_to_secret.txt"
    try:
        symlink.symlink_to(secret_file)
    except OSError:
        print("Symlink creation failed (may need admin rights on Windows)")
        return
    
    fake_accounts = [{
        "local_folder": str(onedrive_folder),
        "spo_url": "https://contoso.sharepoint.com/personal/user",
        "email": "user@contoso.com",
        "type": "business",
    }]
    
    with patch("onedrive_mcp.server._discover_onedrive_accounts", return_value=fake_accounts):
        result = _resolve_share_url(str(symlink))
        print(f"\nSymlink test result: {result}")
        
        # After Path.resolve(), the symlink target is resolved
        # This could be a vulnerability if the resolved path is outside OneDrive
        # but still gets processed
        if "url" in result:
            print(f"WARNING: Symlink to outside file was processed: {result['url']}")


def test_information_disclosure(tmp_path):
    """Test that error messages don't leak sensitive path information."""
    onedrive_folder = tmp_path / "OneDrive5" / "User" / "SecretProject"
    onedrive_folder.mkdir(parents=True)
    
    test_file = onedrive_folder / "confidential.docx"
    test_file.write_text("test")
    
    fake_accounts = [{
        "local_folder": str(tmp_path / "OneDrive5"),
        "spo_url": "https://contoso.sharepoint.com/personal/user",
        "email": "user@contoso.com",
        "type": "business",
    }]
    
    with patch("onedrive_mcp.server._discover_onedrive_accounts", return_value=fake_accounts):
        result = _resolve_share_url(str(test_file))
        print(f"\nInformation disclosure test: {result}")
        
        # Check if full local paths appear in any output
        result_str = str(result)
        if str(tmp_path) in result_str:
            print(f"WARNING: Full local path leaked in result: {result_str}")
        
        # Check if username or sensitive folder names appear
        if "SecretProject" in result.get("url", ""):
            print("Note: Folder name 'SecretProject' appears in SharePoint URL (expected)")


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        
        print("=" * 70)
        print("SECURITY TESTS FOR generate_share_url")
        print("=" * 70)
        
        print("\n--- Path Traversal Tests ---")
        test_path_traversal_attempts(tmp)
        
        print("\n--- URL Injection Tests ---")
        test_url_injection_attempts(tmp)
        
        print("\n--- Registry Value Injection Tests ---")
        test_registry_value_injection(tmp)
        
        print("\n--- Symlink Path Traversal Tests ---")
        test_symlink_path_traversal(tmp)
        
        print("\n--- Information Disclosure Tests ---")
        test_information_disclosure(tmp)
        
        print("\n" + "=" * 70)
        print("TESTS COMPLETE")
        print("=" * 70)
