"""Real browser credential request/reveal/renew/revoke/approval; disposable PostgreSQL fixture."""
import argparse, base64, hashlib, json, shutil, subprocess
from pathlib import Path
from playwright.sync_api import sync_playwright, expect
parser = argparse.ArgumentParser()
for option in ['fixture', 'other-fixture', 'cert', 'report']:
    parser.add_argument('--' + option, required=True)
args = parser.parse_args()
fixture = json.loads(Path(args.fixture).read_text())
other = json.loads(Path(args.other_fixture).read_text())
pub = subprocess.check_output(['openssl','x509','-in',args.cert,'-pubkey','-noout'])
der = subprocess.check_output(['openssl','pkey','-pubin','-outform','DER'],input=pub)
pin = base64.b64encode(hashlib.sha256(der).digest()).decode()
report = {'client': 'SecretHub native Human UI / Chromium', 'tests': []}
def passed(name):
    report['tests'].append({'name': name, 'result': 'pass'})
    print('PASS ' + name)
with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=shutil.which('chromium'), headless=True,
        args=[f'--ignore-certificate-errors-spki-list={pin}', '--proxy-server=direct://', '--no-proxy-server'])
    try:
        page = browser.new_page()
        page.goto('https://127.0.0.1:14666/human/ui')
        page.locator('#email').fill(fixture['email']); page.locator('#password').fill(fixture['password'])
        page.get_by_role('button', name='Unlock access', exact=True).click()
        expect(page.locator('#status')).to_have_text('Signed in',timeout=15000)
        expect(page.locator('#capabilities article')).to_have_count(2)
        assert page.locator('#password').input_value() == ''
        stored = page.evaluate('Object.keys(localStorage)')
        assert stored == ['secrethub-human-device']
        passed('client-derived authentication, memory-only session, cleared password field')
        page.on('dialog', lambda dialog: dialog.accept('60'))
        page.locator('#capabilities article').filter(has_text='postgres-browser / reader ').get_by_role('button',name='Request credential',exact=True).click()
        expect(page.locator('#reveal')).not_to_be_empty(timeout=15000)
        credential = json.loads(page.locator('#reveal').inner_text())
        assert credential['password'] and credential['username']
        expect(page.locator('#leases article')).to_have_count(1)
        page.get_by_role('button',name='Clear credential',exact=True).click()
        expect(page.locator('#reveal')).to_be_empty()
        passed('authorized issuance, one-time reveal, lease rendered, explicit clear')
        page.locator('#leases').get_by_role('button',name='Renew',exact=True).click()
        page.wait_for_timeout(1000)
        expect(page.locator('#status')).to_have_text('Signed in')
        page.locator('#leases').get_by_role('button',name='Revoke',exact=True).click()
        expect(page.locator('#leases')).to_contain_text('revoked',timeout=10000)
        passed('renewal and revocation through the public Core boundary')
        page.locator('#capabilities article').filter(has_text='postgres-browser / reviewed ').get_by_role('button',name='Request approval',exact=True).click()
        expect(page.locator('#approvals')).to_contain_text('pending',timeout=10000)
        expect(page.locator('#approvals').get_by_role('button',name='approve',exact=True)).to_have_count(0)
        approver = browser.new_page()
        approver.goto('https://127.0.0.1:14666/human/ui')
        approver.locator('#email').fill(other['email']); approver.locator('#password').fill(other['password'])
        approver.get_by_role('button',name='Unlock access',exact=True).click()
        expect(approver.locator('#approvals').get_by_role('button',name='approve',exact=True)).to_be_visible(timeout=15000)
        approver.locator('#approvals').get_by_role('button',name='approve',exact=True).click()
        expect(approver.locator('#approvals')).to_contain_text(': approved',timeout=10000)
        expect(approver.locator('#approvals').get_by_role('button',name='Issue approved request',exact=True)).to_have_count(0)
        page.get_by_role('button',name='Refresh',exact=True).click()
        expect(page.locator('#approvals')).to_contain_text(': approved',timeout=10000)
        page.locator('#approvals').get_by_role('button',name='Issue approved request',exact=True).click()
        expect(page.locator('#reveal')).not_to_be_empty(timeout=15000)
        passed('pending approval, policy-approved issuance and short-lived reveal')
        page.get_by_role('button',name='Sign out',exact=True).click()
        expect(page.locator('#status')).to_have_text('Signed out')
        expect(page.locator('#reveal')).to_be_empty()
        expect(page.locator('#workspace')).to_be_hidden()
        passed('sign-out revokes session and clears rendered credential')
        Path(args.report).write_text(json.dumps(report, indent=2))
    finally:
        browser.close()
