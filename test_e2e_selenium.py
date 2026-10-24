"""End-to-End Selenium Test Suite for AgentGuard.
Automates real browser interaction with AgentGuard's dashboard and verifies functionality using Selenium WebDriver.
"""
import sys
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from agentguard.selenium_runner import _create_webdriver

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

def run_tests():
    print("=" * 70)
    print("[START] E2E SELENIUM AUTOMATION SUITE FOR AGENTGUARD")
    print("=" * 70)

    driver = None
    try:
        # Step 1: Initialize Selenium WebDriver
        print("\n[Step 1] Initializing Selenium WebDriver...")
        driver, browser_name = _create_webdriver(timeout=15)
        print(f"[OK] Driver initialized: {browser_name} (Headless Mode)")

        # Step 2: Open AgentGuard Dashboard
        target_url = "http://127.0.0.1:5000/"
        print(f"\n[Step 2] Navigating to AgentGuard Dashboard: {target_url} ...")
        driver.get(target_url)
        wait = WebDriverWait(driver, 15)

        # Step 3: Validate Dashboard Header & Content
        print("\n[Step 3] Verifying Dashboard Header & Key UI Components...")
        header_title = wait.until(EC.presence_of_element_located((By.TAG_NAME, "h1"))).text
        page_title = driver.title
        print(f"   - Page <title>: '{page_title}'")
        print(f"   - <h1> Header:   '{header_title}'")
        assert "AgentGuard" in header_title, f"Expected 'AgentGuard' in header, got '{header_title}'"
        assert "AgentGuard" in page_title, f"Expected 'AgentGuard' in page title, got '{page_title}'"
        print("[OK] Dashboard loaded with correct title and branding!")

        # Step 4: Verify All Dashboard Sections Exist
        print("\n[Step 4] Checking Core Dashboard Sections...")
        panels = driver.find_elements(By.CLASS_NAME, "panel")
        print(f"   - Total dashboard panels found: {len(panels)}")
        assert len(panels) >= 7, f"Expected at least 7 panels, found {len(panels)}"
        print("[OK] Dashboard panels rendered properly.")

        # Step 5: Test Section 11 (Browser Test Runner Form) via Selenium
        print("\n[Step 5] Interacting with Section 11: Automated Browser Test Runner...")
        url_input = wait.until(EC.presence_of_element_located((By.ID, "browser_url")))
        title_input = driver.find_element(By.ID, "browser_expected_title")
        run_btn = driver.find_element(By.ID, "browser_run_btn")

        print("   - Clearing inputs and filling valid target URL...")
        url_input.clear()
        url_input.send_keys("http://127.0.0.1:5000/sut/health")
        title_input.clear()

        print("   - Clicking 'Run Browser Test' button via Selenium...")
        run_btn.click()

        print("   - Waiting for dynamic AJAX result card to update...")
        status_badge = wait.until(
            lambda d: d.find_element(By.ID, "browser_status_badge").text in ("PASS", "FAIL")
        )
        final_badge_text = driver.find_element(By.ID, "browser_status_badge").text
        duration_text = driver.find_element(By.ID, "browser_duration").text
        print(f"   - Outcome: Status={final_badge_text}, Duration={duration_text}")
        assert final_badge_text == "PASS", f"Expected PASS status, got '{final_badge_text}'"

        rows = driver.find_elements(By.XPATH, "//tbody[@id='browser_checks_tbody']/tr")
        print(f"   - Checks executed in browser: {len(rows)}")
        for r in rows:
            print(f"     * {r.text.replace(chr(10), ' | ')}")
        print("[OK] Valid browser test case passed completely via Selenium UI!")

        # Step 6: Test Negative / Security SSRF Block Case via UI
        print("\n[Step 6] Testing Security SSRF Prevention via Selenium UI...")
        url_input.clear()
        url_input.send_keys("http://169.254.169.254/latest/meta-data")
        run_btn.click()

        print("   - Waiting for SSRF rejection...")
        wait.until(lambda d: d.find_element(By.ID, "browser_status_badge").text == "FAIL")
        err_box = driver.find_element(By.ID, "browser_error_box")
        err_text = err_box.text
        print(f"   - Error displayed in UI: '{err_text}'")
        assert "cloud metadata" in err_text.lower(), f"Expected cloud metadata error, got '{err_text}'"
        print("[OK] SSRF attempt was successfully blocked and displayed in UI!")

        # Step 7: Test Application Switcher dropdown
        print("\n[Step 7] Testing Target App Selection via Selenium...")
        app_select = driver.find_element(By.ID, "app_select")
        options = app_select.find_elements(By.TAG_NAME, "option")
        print(f"   - Available applications in dropdown: {len(options)}")
        for opt in options:
            print(f"     * {opt.text}")
        assert len(options) >= 1
        print("[OK] Target application dropdown verified.")

        print("\n" + "=" * 70)
        print("[SUCCESS] ALL SELENIUM TEST CASES PASSED SUCCESSFULLY!")
        print("=" * 70)

    except Exception as e:
        print(f"\n[FAIL] TEST RUNNER FAILED WITH EXCEPTION: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        if driver:
            print("\n[Cleanup] Quitting Selenium WebDriver session...")
            driver.quit()
            print("[OK] WebDriver terminated.")

if __name__ == "__main__":
    run_tests()
