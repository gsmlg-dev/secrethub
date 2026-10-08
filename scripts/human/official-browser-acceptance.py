"""Pinned unmodified Chrome extension black-box login and initial sync. Synthetic fixtures only."""
import argparse, base64, hashlib, json, shutil, subprocess
from pathlib import Path
from playwright.sync_api import sync_playwright, expect
parser = argparse.ArgumentParser()
parser.add_argument('--fixture', required=True)
parser.add_argument('--extension', required=True)
parser.add_argument('--cert', required=True)
parser.add_argument('--profile', required=True)
parser.add_argument('--report', required=True)
args = parser.parse_args()
fixture = json.loads(Path(args.fixture).read_text())
manifest = json.loads((Path(args.extension) / 'manifest.json').read_text())
assert manifest['version'] == '2026.9.3'
Path(args.profile).mkdir(parents=True, mode=0o700)
Path(args.profile).chmod(0o700)
pub = subprocess.check_output(['openssl', 'x509', '-in', args.cert, '-pubkey', '-noout'])
der = subprocess.check_output(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=pub)
pin = base64.b64encode(hashlib.sha256(der).digest()).decode()
ua = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36'
report = {'client': 'Bitwarden Chrome extension', 'version': '2026.9.3', 'tests': []}
with sync_playwright() as p:
    ctx = p.chromium.launch_persistent_context(args.profile, executable_path=shutil.which('chromium'),
        headless=True, user_agent=ua, args=[f'--disable-extensions-except={args.extension}',
        f'--load-extension={args.extension}', f'--ignore-certificate-errors-spki-list={pin}',
        '--proxy-server=direct://', '--no-proxy-server', f'--user-agent={ua}'])
    try:
        worker = ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event('serviceworker', timeout=30000)
        extension_id = worker.url.split('/')[2]
        page = ctx.new_page()
        page.goto(f'chrome-extension://{extension_id}/popup/index.html')
        page.wait_for_timeout(4000)
        if page.get_by_role('button', name='Skip', exact=True).first.is_visible():
            page.get_by_role('button', name='Skip', exact=True).first.click()
        page.get_by_role('button', name='Log in', exact=True).click()
        page.get_by_role('button', name='bitwarden.com', exact=True).click()
        page.get_by_role('menuitem', name='self-hosted').click()
        page.get_by_role('textbox', name='Server URL', exact=True).fill('https://127.0.0.1:14666')
        page.get_by_role('button', name='Save', exact=True).click()
        page.locator('input[type=email]').fill(fixture['email'])
        page.get_by_role('button', name='Continue', exact=True).click()
        page.locator('input[type=password]').fill(fixture['password'])
        page.get_by_role('button', name='Log in', exact=True).last.click()
        expect(page.get_by_role('heading', name='Vault', exact=True)).to_be_visible(timeout=30000)
        loaded_vault = page.get_by_role('searchbox', name='Search', exact=True).or_(
            page.get_by_role('heading', name='Your vault is empty', exact=True))
        expect(loaded_vault).to_be_visible(timeout=30000)
        report['tests'] = [{'name': 'authenticate with self-hosted HTTPS origin and client-derived verifier', 'result':'pass'},
                           {'name': 'initial encrypted personal-vault sync renders unlocked vault', 'result':'pass'}]
        Path(args.report).write_text(json.dumps(report, indent=2))
        for test in report['tests']:
            print('PASS ' + test['name'])
    finally:
        ctx.close()
