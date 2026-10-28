import json
import logging
import os
import platform
import re
import sys
import time
from datetime import timedelta
from html import escape, unescape
from random import uniform
from urllib.parse import unquote, quote, urlsplit

from func_timeout import FunctionTimedOut, func_timeout
from selenium.common import TimeoutException
from selenium.webdriver.chrome.webdriver import WebDriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.expected_conditions import (
    presence_of_element_located, staleness_of, title_is)
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support.wait import WebDriverWait

import utils
from dtos import (STATUS_ERROR, STATUS_OK, ChallengeResolutionResultT,
                  ChallengeResolutionT, HealthResponse, IndexResponse,
                  V1RequestBase, V1ResponseBase)
from sessions import SessionsStorage

ACCESS_DENIED_TITLES = [
    # Cloudflare
    'Access denied',
    # Cloudflare http://bitturk.net/ Firefox
    'Attention Required! | Cloudflare'
]
ACCESS_DENIED_SELECTORS = [
    # Cloudflare
    'div.cf-error-title span.cf-code-label span',
    # Cloudflare http://bitturk.net/ Firefox
    '#cf-error-details div.cf-error-overview h1'
]
CHALLENGE_TITLES = [
    # Cloudflare
    'Just a moment...',
    # DDoS-GUARD
    'DDoS-Guard'
]
CHALLENGE_SELECTORS = [
    # Cloudflare
    '#cf-challenge-running', '.ray_id', '.attack-box', '#cf-please-wait', '#challenge-spinner', '#trk_jschal_js', '#turnstile-wrapper', '.lds-ring',
    # Custom CloudFlare for EbookParadijs, Film-Paleis, MuziekFabriek and Puur-Hollands
    'td.info #js_info',
    # Fairlane / pararius.com
    'div.vc div.text-box h2'
]

TURNSTILE_SELECTORS = [
    "input[name='cf-turnstile-response']"
]

# comix.to's own WAF grants this after its /@waf/verify endpoint accepts a
# Turnstile token from the widget at /@waf/challenge
WAF_PASS_COOKIE = 'waf_pass'

# Pass cookies closer to expiry than this are silently re-solved instead of
# being handed out, so a pinned session never returns cookies that will die
# mid-request. 0 disables the regen check (fresh = not expired at all).
TURNSTILE_REGEN_WINDOW_SECONDS = int(
    os.environ.get('TURNSTILE_REGEN_WINDOW_SECONDS', '300'))

SESSIONS_STORAGE = SessionsStorage()


def test_browser_installation():
    logging.info("Testing web browser installation...")
    logging.info("Platform: " + platform.platform())

    chrome_exe_path = utils.get_chrome_exe_path()
    if chrome_exe_path is None:
        logging.error("Chrome / Chromium web browser not installed!")
        sys.exit(1)
    else:
        logging.info("Chrome / Chromium path: " + chrome_exe_path)

    chrome_major_version = utils.get_chrome_major_version()
    if chrome_major_version == '':
        logging.error("Chrome / Chromium version not detected!")
        sys.exit(1)
    else:
        logging.info("Chrome / Chromium major version: " + chrome_major_version)

    logging.info("Launching web browser...")
    user_agent = utils.get_user_agent()
    logging.info("FlareSolverr User-Agent: " + user_agent)
    logging.info("Test successful!")


def index_endpoint() -> IndexResponse:
    res = IndexResponse({})
    res.msg = "FlareSolverr is ready!"
    res.version = utils.get_flaresolverr_version()
    res.userAgent = utils.get_user_agent()
    return res


def health_endpoint() -> HealthResponse:
    res = HealthResponse({})
    res.status = STATUS_OK
    return res


def controller_v1_endpoint(req: V1RequestBase) -> V1ResponseBase:
    start_ts = int(time.time() * 1000)
    logging.info(f"Incoming request => POST /v1 body: {utils.object_to_dict(req)}")
    res: V1ResponseBase
    try:
        res = _controller_v1_handler(req)
    except Exception as e:
        res = V1ResponseBase({})
        res.__error_500__ = True
        res.status = STATUS_ERROR
        res.message = "Error: " + str(e)
        logging.error(res.message)

    res.startTimestamp = start_ts
    res.endTimestamp = int(time.time() * 1000)
    res.version = utils.get_flaresolverr_version()
    logging.debug(f"Response => POST /v1 body: {utils.object_to_dict(res)}")
    logging.info(f"Response in {(res.endTimestamp - res.startTimestamp) / 1000} s")
    return res


def _controller_v1_handler(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.cmd is None:
        raise Exception("Request parameter 'cmd' is mandatory.")
    if req.headers is not None:
        logging.warning("Request parameter 'headers' was removed in FlareSolverr v2.")
    if req.userAgent is not None:
        logging.warning("Request parameter 'userAgent' was removed in FlareSolverr v2.")

    # set default values
    if req.maxTimeout is None or int(req.maxTimeout) < 1:
        req.maxTimeout = 60000

    # execute the command
    res: V1ResponseBase
    if req.cmd == 'sessions.create':
        res = _cmd_sessions_create(req)
    elif req.cmd == 'sessions.list':
        res = _cmd_sessions_list(req)
    elif req.cmd == 'sessions.destroy':
        res = _cmd_sessions_destroy(req)
    elif req.cmd == 'request.get':
        res = _cmd_request_get(req)
    elif req.cmd == 'request.post':
        res = _cmd_request_post(req)
    else:
        raise Exception(f"Request parameter 'cmd' = '{req.cmd}' is invalid.")

    return res


def _cmd_request_get(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.url is None:
        raise Exception("Request parameter 'url' is mandatory in 'request.get' command.")
    if req.postData is not None:
        raise Exception("Cannot use 'postBody' when sending a GET request.")
    if req.returnRawHtml is not None:
        logging.warning("Request parameter 'returnRawHtml' was removed in FlareSolverr v2.")
    if req.download is not None:
        logging.warning("Request parameter 'download' was removed in FlareSolverr v2.")

    challenge_res = _resolve_challenge(req, 'GET')
    res = V1ResponseBase({})
    res.status = challenge_res.status
    res.message = challenge_res.message
    res.solution = challenge_res.result
    return res


def _cmd_request_post(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.postData is None:
        raise Exception("Request parameter 'postData' is mandatory in 'request.post' command.")
    if req.returnRawHtml is not None:
        logging.warning("Request parameter 'returnRawHtml' was removed in FlareSolverr v2.")
    if req.download is not None:
        logging.warning("Request parameter 'download' was removed in FlareSolverr v2.")

    challenge_res = _resolve_challenge(req, 'POST')
    res = V1ResponseBase({})
    res.status = challenge_res.status
    res.message = challenge_res.message
    res.solution = challenge_res.result
    return res


def _cmd_sessions_create(req: V1RequestBase) -> V1ResponseBase:
    logging.debug("Creating new session...")

    session, fresh = SESSIONS_STORAGE.create(session_id=req.session, proxy=req.proxy)
    session_id = session.session_id

    if not fresh:
        return V1ResponseBase({
            "status": STATUS_OK,
            "message": "Session already exists.",
            "session": session_id
        })

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "Session created successfully.",
        "session": session_id
    })


def _cmd_sessions_list(req: V1RequestBase) -> V1ResponseBase:
    session_ids = SESSIONS_STORAGE.session_ids()

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "",
        "sessions": session_ids
    })


def _cmd_sessions_destroy(req: V1RequestBase) -> V1ResponseBase:
    session_id = req.session
    existed = SESSIONS_STORAGE.destroy(session_id)

    if not existed:
        raise Exception("The session doesn't exist.")

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "The session has been removed."
    })


def _resolve_challenge(req: V1RequestBase, method: str) -> ChallengeResolutionT:
    timeout = int(req.maxTimeout) / 1000
    driver = None
    try:
        if req.session:
            session_id = req.session
            ttl = timedelta(minutes=req.session_ttl_minutes) if req.session_ttl_minutes else None
            session, fresh = SESSIONS_STORAGE.get(session_id, ttl)

            if fresh:
                logging.debug(f"new session created to perform the request (session_id={session_id})")
            else:
                logging.debug(f"existing session is used to perform the request (session_id={session_id}, "
                              f"lifetime={str(session.lifetime())}, ttl={str(ttl)})")

            driver = session.driver
        else:
            driver = utils.get_webdriver(req.proxy)
            logging.debug('New instance of webdriver has been created to perform the request')
        return func_timeout(timeout, _evil_logic, (req, driver, method))
    except FunctionTimedOut:
        raise Exception(f'Error solving the challenge. Timeout after {timeout} seconds.')
    except Exception as e:
        raise Exception('Error solving the challenge. ' + str(e).replace('\n', '\\n'))
    finally:
        if not req.session and driver is not None:
            if utils.PLATFORM_VERSION == "nt":
                driver.close()
            driver.quit()
            logging.debug('A used instance of webdriver has been destroyed')


def click_verify(driver: WebDriver, num_tabs: int = 1):
    try:
        logging.debug("Try to find the Cloudflare verify checkbox...")
        actions = ActionChains(driver)
        actions.pause(5 + uniform(0.1, 0.5))
        for _ in range(num_tabs):
            actions.send_keys(Keys.TAB).pause(0.1 + uniform(0.02, 0.1))
        actions.pause(1 + uniform(0.1, 0.5))
        actions.send_keys(Keys.SPACE).perform()

        logging.debug(f"Cloudflare verify checkbox clicked after {num_tabs} tabs!")
    except Exception:
        logging.debug("Cloudflare verify checkbox not found on the page.")
    finally:
        driver.switch_to.default_content()

    try:
        logging.debug("Try to find the Cloudflare 'Verify you are human' button...")
        button = driver.find_element(
            by=By.XPATH,
            value="//input[@type='button' and @value='Verify you are human']",
        )
        if button:
            actions = ActionChains(driver)
            actions.move_to_element_with_offset(button, 5, 7)
            actions.click(button)
            actions.perform()
            logging.debug("The Cloudflare 'Verify you are human' button found and clicked!")
    except Exception:
        logging.debug("The Cloudflare 'Verify you are human' button not found on the page.")

    time.sleep(2)

def _get_turnstile_token(driver: WebDriver, tabs: int):
    token_input = driver.find_element(By.CSS_SELECTOR, "input[name='cf-turnstile-response']")
    current_value = token_input.get_attribute("value")
    while True:
        click_verify(driver, num_tabs=tabs)
        turnstile_token = token_input.get_attribute("value")
        if turnstile_token:
            if turnstile_token != current_value:
                logging.info(f"Turnstile token: {turnstile_token}")
                return turnstile_token
        logging.debug(f"Failed to extract token possibly click failed")

        # reset focus
        driver.execute_script("""
            let old = document.getElementById('__focus_helper');
            if (old) old.remove();

            let el = document.createElement('button');
            el.id = '__focus_helper';
            el.style.position = 'fixed';
            el.style.top = '0';
            el.style.left = '0';
            el.style.opacity = '0.01';
            el.style.pointerEvents = 'none';
            document.body.prepend(el);
            el.focus();
        """)
        time.sleep(1)

def _resolve_turnstile_captcha(req: V1RequestBase, driver: WebDriver):
    turnstile_token = None
    if req.tabs_till_verify is not None:
        logging.debug(f'Navigating to... {req.url} in order to pass the turnstile challenge')
        driver.get(req.url)

        turnstile_challenge_found = False
        for selector in TURNSTILE_SELECTORS:
            found_elements = driver.find_elements(By.CSS_SELECTOR, selector)
            if len(found_elements) > 0:
                turnstile_challenge_found = True
                logging.info("Turnstile challenge detected. Selector found: " + selector)
                break
        if turnstile_challenge_found:
            turnstile_token = _get_turnstile_token(driver=driver, tabs=req.tabs_till_verify)
        else:
            logging.debug(f'Turnstile challenge not found')
    return turnstile_token

def _turnstile_token_value(driver: WebDriver):
    try:
        return driver.execute_script(
            "var el = document.querySelector(\"input[name='cf-turnstile-response']\");"
            "return el ? (el.value || '') : '';") or ''
    except Exception:
        return ''


def _click_turnstile_widget(driver: WebDriver):
    """Real mouse click on the Turnstile checkbox inside its iframe."""
    try:
        driver.switch_to.default_content()
        iframes = driver.find_elements(
            By.CSS_SELECTOR, "iframe[src*='challenges.cloudflare.com']")
        if not iframes:
            return False
        box = iframes[0]
        height = box.size.get('height', 65) if box.size else 65
        actions = ActionChains(driver)
        actions.move_to_element_with_offset(box, 30, max(height // 2, 5))
        actions.click()
        actions.perform()
        logging.debug("Clicked inside the Turnstile iframe")
        return True
    except Exception as e:
        logging.debug(f"Turnstile iframe click failed: {e}")
        return False
    finally:
        try:
            driver.switch_to.default_content()
        except Exception:
            pass


def _turnstile_widget_present(driver: WebDriver):
    try:
        return bool(driver.execute_script(
            "return !!document.querySelector(\"input[name='cf-turnstile-response']\");"))
    except Exception:
        return False


def _has_pass_cookie(driver: WebDriver):
    try:
        return any(c.get('name') == WAF_PASS_COOKIE for c in driver.get_cookies())
    except Exception:
        return False


def _pass_cookie(driver: WebDriver, name: str):
    """(expiry_epoch, value) of a cookie in this driver's jar, or (None, None)."""
    try:
        for c in driver.get_cookies():
            if c.get('name') == name:
                return c.get('expiry'), c.get('value')
    except Exception:
        pass
    return None, None


def _waf_jar_state(driver: WebDriver, url: str):
    """How the target site's pass cookies are doing in this driver's jar.

    'fresh' - every required pass cookie present and outside the regen window
    'stale' - present but inside the regen window
    'cold'  - a required cookie is missing; also the answer when this driver is
              not sitting on the target host, since Selenium only exposes
              cookies for the current domain and we cannot inspect the jar
    Returns (state, seconds_to_expiry of the governing cookie).
    """
    try:
        target_host = (urlsplit(url).hostname or '').removeprefix('www.')
    except Exception:
        return 'cold', None
    try:
        current_host = (urlsplit(driver.current_url or '').hostname or '').removeprefix('www.')
    except Exception:
        current_host = ''
    if not target_host or current_host != target_host:
        return 'cold', None

    required = ['cf_clearance']
    if 'comix.to' in target_host:
        required.append(WAF_PASS_COOKIE)
    governing = None
    for name in required:
        expiry, _ = _pass_cookie(driver, name)
        if expiry is None:
            return 'cold', None
        remaining = expiry - time.time()
        if governing is None or remaining < governing:
            governing = remaining
    return ('fresh' if governing > TURNSTILE_REGEN_WINDOW_SECONDS else 'stale'), governing


def _snap_state(driver: WebDriver, start_url: str, before_names=frozenset()):
    """(token, verify_trail_signal, url_changed) for any site's own verify flow."""
    token = _turnstile_token_value(driver)
    new_cookie = False
    try:
        for c in driver.get_cookies():
            if c.get('name') not in before_names:
                new_cookie = True
                break
    except Exception:
        pass
    try:
        url_changed = start_url is not None and driver.current_url != start_url
    except Exception:
        url_changed = False
    return token, new_cookie, url_changed


def _solve_site_turnstile(driver: WebDriver, deadline: float, force: bool = False):
    """Solve a page-embedded Turnstile widget.

    comix.to's own WAF (/@waf/challenge) is special-cased: its verify only
    counts once the granted `waf_pass` cookie is actually in the jar - an
    unverified jar makes every subsequent API call 403 - so we hold until it
    lands. Any other site gets the fast generic treatment (token, redirect or
    new cookie, then a short trail).

    `force` (set when the jar holds an about-to-expire pass) bypasses the
    short-circuits that would otherwise accept the existing pass and keeps
    clicking until the verify mints a renewed one.
    """
    try:
        current_url = driver.current_url
    except Exception:
        current_url = ''
    comix_waf = 'comix.to' in current_url and '/@waf/challenge' in current_url

    if _turnstile_token_value(driver) and not force:
        logging.debug("Turnstile widget already carries a token")
        return True
    # the widget may not be rendered yet (a Cloudflare JS-only interstitial can
    # still be clearing); for the comix WAF that must not matter - the point is
    # to hold until waf_pass lands, and clicks are harmless meanwhile
    if not comix_waf and not _turnstile_widget_present(driver):
        logging.debug("No Turnstile widget on this page")
        return False
    try:
        before_names = frozenset(c.get('name') for c in driver.get_cookies())
    except Exception:
        before_names = frozenset()
    logging.info(f"Embedded Turnstile widget detected ({'comix waf' if comix_waf else 'generic'}); attempting to solve it")

    if comix_waf:
        # the verify POST that grants waf_pass is followed by a redirect away
        # from the challenge page - so the redirect IS the success signal, and
        # the pass cookie is guaranteed to be in the jar by then. A Cloudflare
        # interstitial may sit in front; the clicks move that along too.
        old_expiry, old_value = _pass_cookie(driver, WAF_PASS_COOKIE)
        attempts = 0
        while time.monotonic() < deadline:
            attempts += 1
            _click_turnstile_widget(driver)
            click_verify(driver, num_tabs=1)
            # poll fast: token -> verify -> Set-Cookie -> redirect all in ~2s
            for _ in range(5):
                time.sleep(0.8)
                try:
                    if '/@waf/challenge' not in (driver.current_url or ''):
                        logging.info(f"Comix WAF passed after {attempts} click attempts "
                                     f"(redirected to {driver.current_url})")
                        return True
                except Exception:
                    pass
                expiry, value = _pass_cookie(driver, WAF_PASS_COOKIE)
                if value is not None and (not force or (value != old_value or expiry != old_expiry)):
                    logging.info(f"Comix WAF passed after {attempts} click attempts "
                                 f"({'renewed pass' if force else 'waf_pass set'})")
                    return True
            logging.debug(f"Comix WAF not passed yet (attempt {attempts})")
        logging.warning("Comix WAF did not pass before the deadline")
        return False

    try:
        start_url = driver.current_url
    except Exception:
        start_url = None

    def generic_done():
        token, new_cookie, url_changed = _snap_state(driver, start_url, before_names)
        return bool(token) or new_cookie or url_changed

    # non-interactive widgets: give the token a couple of seconds to appear
    for _ in range(2):
        time.sleep(1)
        if generic_done():
            return _trail_verify(driver, deadline, before_names)
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        _click_turnstile_widget(driver)
        click_verify(driver, num_tabs=1)
        # poll fast: tokens are issued within a second of a successful click
        for _ in range(4):
            time.sleep(0.75)
            if generic_done():
                logging.info(f"Turnstile widget solved after {attempts} attempts (token: {bool(_turnstile_token_value(driver))})")
                return _trail_verify(driver, deadline, before_names)
        logging.debug(f"Turnstile widget not solved yet (attempt {attempts})")
    logging.debug("Turnstile widget did not resolve before the deadline")
    return False


def _trail_verify(driver: WebDriver, deadline: float, before_names=frozenset()):
    """Generic sites: give the page a moment to finish its own verify POST and
    let the granted cookie land, returning as soon as anything confirms it."""
    for _ in range(6):
        time.sleep(1)
        if _has_pass_cookie(driver):
            return True
        _, new_cookie, url_changed = _snap_state(driver, None, before_names)
        if new_cookie or url_changed:
            return True
        if time.monotonic() > deadline:
            break
    return _has_pass_cookie(driver)


def _evil_logic(req: V1RequestBase, driver: WebDriver, method: str) -> ChallengeResolutionT:
    res = ChallengeResolutionT({})
    res.status = STATUS_OK
    res.message = ""

    # optionally block resources like images/css/fonts using CDP
    disable_media = utils.get_config_disable_media()
    if req.disableMedia is not None:
        disable_media = req.disableMedia
    if disable_media:
        block_urls = [
            # Images
            "*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp", "*.bmp", "*.svg", "*.ico",
            "*.PNG", "*.JPG", "*.JPEG", "*.GIF", "*.WEBP", "*.BMP", "*.SVG", "*.ICO",
            "*.tiff", "*.tif", "*.jpe", "*.apng", "*.avif", "*.heic", "*.heif",
            "*.TIFF", "*.TIF", "*.JPE", "*.APNG", "*.AVIF", "*.HEIC", "*.HEIF",
            # Stylesheets
            "*.css",
            "*.CSS",
            # Fonts
            "*.woff", "*.woff2", "*.ttf", "*.otf", "*.eot",
            "*.WOFF", "*.WOFF2", "*.TTF", "*.OTF", "*.EOT"
        ]
        try:
            logging.debug("Network.setBlockedURLs: %s", block_urls)
            driver.execute_cdp_cmd("Network.enable", {})
            driver.execute_cdp_cmd("Network.setBlockedURLs", {"urls": block_urls})
        except Exception:
            # if CDP commands are not available or fail, ignore and continue
            logging.debug("Network.setBlockedURLs failed or unsupported on this webdriver")

    # navigate to the page
    logging.debug(f"Navigating to... {req.url}")
    turnstile_token = None

    if method == "POST":
        _post_request(req, driver)
    else:
        if req.tabs_till_verify is None:
            jar_state, jar_expiry_in = 'cold', None
            if os.environ.get('TURNSTILE_AUTO_SOLVE', 'true').lower() == 'true':
                try:
                    jar_state, jar_expiry_in = _waf_jar_state(driver, req.url)
                except Exception as e:
                    logging.debug(f"WAF jar check failed: {e}")
            driver.get(req.url)
            # Pages can embed their own Turnstile widget (e.g. comix.to
            # /@waf/challenge) and may have a callback.
            if os.environ.get('TURNSTILE_AUTO_SOLVE', 'true').lower() == 'true':
                if jar_state == 'fresh':
                    logging.info(f"Warm jar: pass cookies still valid "
                                 f"(expires in {int(jar_expiry_in or 0)}s); skipping Turnstile solve")
                else:
                    try:
                        budget = min(60.0, max(10.0, int(req.maxTimeout) / 1000 - 15.0))
                        turnstile_deadline = time.monotonic() + budget
                        if jar_state == 'stale':
                            logging.info(f"Stale pass cookie (expires in {int(jar_expiry_in or 0)}s); "
                                         "forcing a renewed solve")
                        _solve_site_turnstile(
                            driver, turnstile_deadline, force=jar_state == 'stale')
                    except Exception as e:
                        logging.debug(f"Turnstile auto-solve skipped: {e}")
        else:
            turnstile_token = _resolve_turnstile_captcha(req, driver)

    # set cookies if required
    if req.cookies is not None and len(req.cookies) > 0:
        logging.debug(f'Setting cookies...')
        for cookie in req.cookies:
            driver.delete_cookie(cookie['name'])
            driver.add_cookie(cookie)
        # reload the page
        if method == 'POST':
            _post_request(req, driver)
        else:
            driver.get(req.url)

    # wait for the page
    if utils.get_config_log_html():
        logging.debug(f"Response HTML:\n{driver.page_source}")
    html_element = driver.find_element(By.TAG_NAME, "html")
    page_title = driver.title

    # find access denied titles
    for title in ACCESS_DENIED_TITLES:
        if page_title.startswith(title):
            raise Exception('Cloudflare has blocked this request. '
                            'Probably your IP is banned for this site, check in your web browser.')
    # find access denied selectors
    for selector in ACCESS_DENIED_SELECTORS:
        found_elements = driver.find_elements(By.CSS_SELECTOR, selector)
        if len(found_elements) > 0:
            raise Exception('Cloudflare has blocked this request. '
                            'Probably your IP is banned for this site, check in your web browser.')

    # find challenge by title
    challenge_found = False
    for title in CHALLENGE_TITLES:
        if title.lower() == page_title.lower():
            challenge_found = True
            logging.info("Challenge detected. Title found: " + page_title)
            break
    if not challenge_found:
        # find challenge by selectors
        for selector in CHALLENGE_SELECTORS:
            found_elements = driver.find_elements(By.CSS_SELECTOR, selector)
            if len(found_elements) > 0:
                challenge_found = True
                logging.info("Challenge detected. Selector found: " + selector)
                break

    browser_wait_timeout = utils.get_config_browser_wait_timeout()
    attempt = 0
    if challenge_found:
        while True:
            try:
                attempt = attempt + 1
                # wait until the title changes
                for title in CHALLENGE_TITLES:
                    logging.debug("Waiting for title (attempt " + str(attempt) + "): " + title)
                    WebDriverWait(driver, browser_wait_timeout).until_not(title_is(title))

                # then wait until all the selectors disappear
                for selector in CHALLENGE_SELECTORS:
                    logging.debug("Waiting for selector (attempt " + str(attempt) + "): " + selector)
                    WebDriverWait(driver, browser_wait_timeout).until_not(
                        presence_of_element_located((By.CSS_SELECTOR, selector)))

                # all elements not found
                break

            except TimeoutException:
                logging.debug("Timeout waiting for selector")

                click_verify(driver)

                # update the html (cloudflare reloads the page every 5 s)
                html_element = driver.find_element(By.TAG_NAME, "html")

        # waits until cloudflare redirection ends
        logging.debug("Waiting for redirect")
        # noinspection PyBroadException
        try:
            WebDriverWait(driver, browser_wait_timeout).until(staleness_of(html_element))
        except Exception:
            logging.debug("Timeout waiting for redirect")

        logging.info("Challenge solved!")
        res.message = "Challenge solved!"
    else:
        logging.info("Challenge not detected!")
        res.message = "Challenge not detected!"

    challenge_res = ChallengeResolutionResultT({})
    challenge_res.url = driver.current_url
    challenge_res.status = 200  # todo: fix, selenium not provides this info
    challenge_res.userAgent = utils.get_user_agent(driver)
    challenge_res.turnstile_token = turnstile_token

    if not req.returnOnlyCookies:
        challenge_res.headers = {}  # todo: fix, selenium not provides this info

        if req.waitInSeconds and req.waitInSeconds > 0:
            logging.info("Waiting " + str(req.waitInSeconds) + " seconds before returning the response...")
            time.sleep(req.waitInSeconds)

        # a JSON POST keeps the pristine response body: document.write() would wrap
        # it in <html><head></head><body>...</body></html>
        challenge_res.response = _unwrap_json_response(driver.page_source)

    if req.returnScreenshot:
        challenge_res.screenshot = driver.get_screenshot_as_base64()

    # Get cookies after all waits to capture cookies set during JavaScript execution
    challenge_res.cookies = driver.get_cookies()

    res.result = challenge_res
    return res


_JSON_RESPONSE_WRAPPER = re.compile(
    r'\A\s*<html\s*>\s*<head\s*>\s*</head\s*>\s*<body\s*>(?P<body>.*)</body\s*>\s*</html\s*>\s*\Z',
    re.DOTALL | re.IGNORECASE)


def _unwrap_json_response(html_response: str) -> str:
    """Return the JSON body of an empty document shell wrapping it.

    document.write() parses the POST response as HTML, so a JSON body comes back
    from page_source nested in <html><head></head><body>...</body></html>. Real
    HTML pages have content in <head>, so they don't match and pass through.
    """
    match = _JSON_RESPONSE_WRAPPER.match(html_response)
    if match is None:
        return html_response
    body = unescape(match.group('body')).strip()
    try:
        json.loads(body)
    except ValueError:
        return html_response  # not JSON, leave the response alone
    return body


def _post_request(req: V1RequestBase, driver: WebDriver):
    post_data = req.postData if req.postData and req.postData[0] != '?' else req.postData[1:] if req.postData else ''

    # If postData is valid JSON, use fetch() with application/json to preserve
    # numeric and boolean types. Form-encoded POST converts all values to strings,
    # which breaks APIs that require numbers (e.g. feeRate: 50 becomes "50").
    stripped = post_data.strip()
    if stripped.startswith(('{', '[')):
        try:
            json.loads(stripped)
            _json_post_request(req, driver, stripped)
            return
        except (json.JSONDecodeError, ValueError):
            pass  # not valid JSON — fall through to form-encoded approach

    post_form = f'<form id="hackForm" action="{req.url}" method="POST">'
    pairs = post_data.split('&')
    for pair in pairs:
        parts = pair.split('=', 1)
        # noinspection PyBroadException
        try:
            name = unquote(parts[0])
        except Exception:
            name = parts[0]
        if name == 'submit':
            continue
        # noinspection PyBroadException
        try:
            value = unquote(parts[1]) if len(parts) > 1 else ''
        except Exception:
            value = parts[1] if len(parts) > 1 else ''
        # Protection of " character, for syntax
        value=value.replace('"','&quot;')
        post_form += f'<input type="text" name="{escape(quote(name))}" value="{escape(quote(value))}"><br>'
    post_form += '</form>'
    html_content = f"""
        <!DOCTYPE html>
        <html>
        <body>
            {post_form}
            <script>document.getElementById('hackForm').submit();</script>
        </body>
        </html>"""
    driver.get("data:text/html;charset=utf-8,{html_content}".format(html_content=html_content))


def _origin_url(url: str) -> str:
    """Return the origin of url (scheme://host[:port]/) to use as fetch() context.

    Navigating to the API endpoint itself is unreliable: a GET on a POST-only
    endpoint replies 405, and an endpoint answering with a non-HTML
    Content-Type (application/json) or Content-Disposition makes Chrome
    download it, leaving no document at that origin to run fetch() from.
    The origin root always serves an HTML document.
    """
    parts = urlsplit(url if '://' in url else 'http://' + url)
    host = parts.netloc.rsplit('@', 1)[-1]  # drop any userinfo
    if not parts.scheme or not host or any(c.isspace() for c in host):
        logging.debug("Could not extract an origin from %s, using it as-is", url)
        return url
    return "%s://%s/" % (parts.scheme, parts.netloc)


def _json_post_request(req: V1RequestBase, driver: WebDriver, post_data: str):
    """Send a JSON POST using fetch() so numeric/boolean types are preserved.

    Navigates to the origin of the target URL first (GET) to establish a
    same-origin context, which allows the subsequent fetch() to bypass CORS
    restrictions. The fetch response overwrites the page so driver.page_source
    contains it.
    """
    logging.debug("JSON postData detected, using fetch() with Content-Type: application/json")
    logging.debug("JSON POST body (%d bytes): %s", len(post_data), post_data)

    origin = _origin_url(req.url)
    logging.debug("JSON GET %s first, to get a same-origin context for the POST to %s", origin, req.url)
    driver.get(origin)

    try:
        landed = driver.execute_script("return location.origin")
        expected = origin.rstrip('/')
        if landed != expected:
            logging.warning("  the GET to %s landed on origin %s, not %s. The POST will be "
                            "cross-origin and CORS will block it.", origin, landed, expected)
    except Exception as e:
        logging.debug("  could not read location.origin: %s", e)

    script = """
        var callback = arguments[arguments.length - 1];
        var ctx = {
            pageUrl: location.href,
            origin: location.origin,
            readyState: document.readyState
        };
        fetch(arguments[0], {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: arguments[1]
        }).then(function(response) {
            return response.text().then(function(text) {
                document.open();
                document.write(text);
                document.close();
                callback({
                    ok: true,
                    status: response.status,
                    statusText: response.statusText,
                    responseUrl: response.url,
                    pageUrl: ctx.pageUrl,
                    origin: ctx.origin,
                    readyState: ctx.readyState
                });
            });
        }).catch(function(e) {
            callback({
                ok: false,
                name: e.name,
                message: e.message,
                stack: e.stack,
                pageUrl: ctx.pageUrl,
                origin: ctx.origin,
                readyState: ctx.readyState
            });
        });
    """
    result = driver.execute_async_script(script, req.url, post_data)
    if isinstance(result, dict) and not result.get('ok'):
        _log_json_post_failure(req, driver, post_data, result)


def _log_json_post_failure(req: V1RequestBase, driver: WebDriver, post_data: str, err: dict):
    """Log why fetch() reported a generic "Failed to fetch".

    fetch() rejects with the same opaque TypeError for every network-layer
    problem (CORS, CSP, mixed content, TLS, DNS, refused connection...), so the
    JS error alone is useless. Chrome logs the actual cause in the console,
    which is collected through the driver's 'browser' log.
    """
    logging.warning("JSON POST fetch() failed: %s: %s", err.get('name'), err.get('message'))
    logging.warning("  request url: %s", req.url)
    logging.warning("  page after GET: %s (origin=%s, readyState=%s)",
                    err.get('pageUrl'), err.get('origin'), err.get('readyState'))
    if err.get('stack'):
        logging.debug("  fetch stack: %s", err['stack'])

    # a redirect on the GET (http -> https, login bounce, api -> www, apex -> www)
    # moves the page to another origin, so the POST becomes cross-origin and CORS kills it
    try:
        page_origin = err.get('origin')
        target_origin = _origin_url(req.url).rstrip('/')
        if page_origin and target_origin and page_origin != target_origin:
            logging.warning("  ORIGIN MISMATCH: the GET landed on %s but the POST goes to %s. "
                            "The fetch is cross-origin and will be blocked unless the response "
                            "has Access-Control-Allow-Origin.", page_origin, target_origin)
    except Exception as e:
        logging.debug("  could not compare origins: %s", e)

    # the console holds the real reason, e.g.
    # "blocked by CORS policy: No 'Access-Control-Allow-Origin' header is present...",
    # "violates the following Content Security Policy directive: connect-src ...",
    # "net::ERR_CONNECTION_REFUSED", "net::ERR_NAME_NOT_RESOLVED", "Mixed Content"
    try:
        console = driver.get_log('browser') or []
    except Exception as e:
        console = []
        logging.debug("  browser console log unavailable (is goog:loggingPrefs set?): %s", e)

    noisy = ('favicon', 'devtools', 'download the react', 'source map')
    for entry in console:
        try:
            text = entry.get('message', '')
            level = entry.get('level', '')
            origin = entry.get('source', '')
            if not any(n in text.lower() for n in noisy):
                logging.warning("  [console:%s/%s] %s", level, origin, text)
        except Exception:
            pass

    logging.warning("  POST was NOT sent successfully; page_source will not contain "
                    "the API response. Run with LOG_LEVEL=debug for the body and stack.")
