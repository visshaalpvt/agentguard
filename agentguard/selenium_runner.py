"""Selenium Browser Testing Runner for AgentGuard.
Automates browser verification using Selenium WebDriver with SSRF protection and structured PASS/FAIL reporting.
"""
import glob
import os
import time
from urllib.parse import urlparse
from .security import validate_target_url


def _find_cached_driver(browser_name: str) -> str | None:
    """Finds cached webdriver executable in user cache if available."""
    user_home = os.path.expanduser("~")
    base_cache = os.path.join(user_home, ".cache", "selenium", browser_name)
    if not os.path.exists(base_cache):
        return None
    patterns = [
        os.path.join(base_cache, "**", f"{browser_name}.exe"),
        os.path.join(base_cache, "**", "msedgedriver.exe"),
        os.path.join(base_cache, "**", "chromedriver.exe"),
    ]
    for pattern in patterns:
        matches = glob.glob(pattern, recursive=True)
        if matches:
            return matches[0]
    return None


def _create_webdriver(timeout: int = 10):
    """Initializes a headless Edge or Chrome WebDriver instance."""
    from selenium import webdriver
    from selenium.webdriver.edge.options import Options as EdgeOptions
    from selenium.webdriver.edge.service import Service as EdgeService
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.chrome.service import Service as ChromeService

    errors = []

    # 1. Try Microsoft Edge (Standard on Windows)
    try:
        edge_opts = EdgeOptions()
        edge_opts.add_argument("--headless=new")
        edge_opts.add_argument("--disable-gpu")
        edge_opts.add_argument("--no-sandbox")
        edge_opts.add_argument("--disable-dev-shm-usage")
        edge_opts.add_argument("--window-size=1280,800")

        cached_edge = _find_cached_driver("msedgedriver")
        if cached_edge and os.path.exists(cached_edge):
            service = EdgeService(executable_path=cached_edge)
            driver = webdriver.Edge(service=service, options=edge_opts)
        else:
            driver = webdriver.Edge(options=edge_opts)

        driver.set_page_load_timeout(timeout)
        return driver, "MicrosoftEdge"
    except Exception as e:
        errors.append(f"Edge: {e}")

    # 2. Try Google Chrome
    try:
        chrome_opts = ChromeOptions()
        chrome_opts.add_argument("--headless=new")
        chrome_opts.add_argument("--disable-gpu")
        chrome_opts.add_argument("--no-sandbox")
        chrome_opts.add_argument("--disable-dev-shm-usage")
        chrome_opts.add_argument("--window-size=1280,800")

        cached_chrome = _find_cached_driver("chromedriver")
        if cached_chrome and os.path.exists(cached_chrome):
            service = ChromeService(executable_path=cached_chrome)
            driver = webdriver.Chrome(service=service, options=chrome_opts)
        else:
            driver = webdriver.Chrome(options=chrome_opts)

        driver.set_page_load_timeout(timeout)
        return driver, "Chrome"
    except Exception as e:
        errors.append(f"Chrome: {e}")

    raise RuntimeError(f"Unable to initialize WebDriver: {'; '.join(errors)}")


def run_browser_test(url: str, expected_title: str | None = None, timeout: int = 10) -> dict:
    """
    Executes a structured browser verification test against the given target URL.
    Enforces SSRF prevention, bounds execution timeouts, and guarantees cleanup.
    """
    start_time = time.time()
    tests = []
    page_title = None
    final_url = None
    driver = None
    error_msg = None

    # BG-004: Validate Target URL
    is_valid, validation_err = validate_target_url(url, allow_localhost=True)
    if not is_valid:
        tests.append({
            "id": "BG-004",
            "name": "Target URL validation",
            "status": "FAIL",
            "detail": validation_err
        })
        return {
            "status": "FAIL",
            "url": url,
            "page_title": None,
            "final_url": None,
            "duration_ms": round((time.time() - start_time) * 1000, 2),
            "tests": tests,
            "error": f"URL validation failed: {validation_err}"
        }

    tests.append({
        "id": "BG-004",
        "name": "Target URL validation",
        "status": "PASS",
        "detail": "URL syntax and destination pass SSRF security checks."
    })

    try:
        # BG-001: Browser Starts
        try:
            driver, browser_name = _create_webdriver(timeout=timeout)
            tests.append({
                "id": "BG-001",
                "name": "Browser initialization",
                "status": "PASS",
                "detail": f"Headless {browser_name} WebDriver started successfully."
            })
        except Exception as e:
            tests.append({
                "id": "BG-001",
                "name": "Browser initialization",
                "status": "FAIL",
                "detail": str(e)
            })
            raise

        # BG-002: Page Loads
        try:
            driver.get(url)
            final_url = driver.current_url
            tests.append({
                "id": "BG-002",
                "name": "Page navigation & load",
                "status": "PASS",
                "detail": f"Navigated successfully to {final_url}"
            })
        except Exception as e:
            tests.append({
                "id": "BG-002",
                "name": "Page navigation & load",
                "status": "FAIL",
                "detail": f"Navigation failed: {e}"
            })
            raise

        # Check redirected URL against SSRF policy as well
        if final_url and final_url != url:
            valid_dest, dest_err = validate_target_url(final_url, allow_localhost=True)
            if not valid_dest:
                tests.append({
                    "id": "BG-004",
                    "name": "Redirect destination validation",
                    "status": "FAIL",
                    "detail": f"Navigation redirected to prohibited location: {dest_err}"
                })
                raise RuntimeError(f"Prohibited redirect: {dest_err}")

        # BG-003: Page Title
        page_title = driver.title or ""
        if expected_title:
            if expected_title.lower() in page_title.lower():
                tests.append({
                    "id": "BG-003",
                    "name": "Page title validation",
                    "status": "PASS",
                    "detail": f"Page title '{page_title}' matched expected filter '{expected_title}'."
                })
            else:
                tests.append({
                    "id": "BG-003",
                    "name": "Page title validation",
                    "status": "FAIL",
                    "detail": f"Page title '{page_title}' did not match expected '{expected_title}'."
                })
        else:
            # Basic validation: Page loaded and returned a title string
            tests.append({
                "id": "BG-003",
                "name": "Page title retrieval",
                "status": "PASS",
                "detail": f"Page title retrieved: '{page_title}'."
            })

    except Exception as e:
        error_msg = str(e)
        tests.append({
            "id": "BG-005",
            "name": "Execution error handling",
            "status": "FAIL",
            "detail": error_msg
        })
    finally:
        # BG-006: Cleanup
        if driver is not None:
            try:
                driver.quit()
                tests.append({
                    "id": "BG-006",
                    "name": "WebDriver session cleanup",
                    "status": "PASS",
                    "detail": "Browser session terminated and resources released."
                })
            except Exception as cleanup_err:
                tests.append({
                    "id": "BG-006",
                    "name": "WebDriver session cleanup",
                    "status": "FAIL",
                    "detail": f"Error terminating session: {cleanup_err}"
                })

    has_failures = any(t["status"] == "FAIL" for t in tests)
    overall_status = "FAIL" if has_failures else "PASS"

    return {
        "status": overall_status,
        "url": url,
        "page_title": page_title,
        "final_url": final_url,
        "duration_ms": round((time.time() - start_time) * 1000, 2),
        "tests": tests,
        "error": error_msg
    }
