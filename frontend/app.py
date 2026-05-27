import base64
import datetime as dt
import json

from nicegui import ui

from common.config import AAA_URL, CA_URL, CM_URL, FRONTEND_PORT, KM_URL, RM_URL, SERVICE_IDENTITIES
from common.http_client import request_json
from common.logging_utils import configure_logging
from common.security.asymmetric_cryptography import AsymmetricCryptography
from common.security.certificate_utils import CertificateUtils
from common.security.demo_ca_builder import DemoCABuilder
from common.security.symmetric_cryptography import SymmetricCryptography

logger = configure_logging("frontend")
utils = CertificateUtils()
DemoCABuilder().ensure_demo_pki()

SERVICE_URLS = {
    "AAA": AAA_URL,
    "CA": CA_URL,
    "CM": CM_URL,
    "KM": KM_URL,
    "RM": RM_URL,
}

PAGE_WIDTH = 'w-full max-w-[1600px] mx-auto'
COLUMN_WIDTH = 'w-full max-w-[760px] gap-4'
BUTTON_ROW = 'w-full gap-2 justify-center flex-wrap'
MISSION_LOG_CLEAR_TIMES = {service_name: '' for service_name in SERVICE_URLS}


def action_button(label: str, on_click, color: str = 'primary'):
    button_classes = {
        'primary': 'bg-slate-800/95 text-slate-100 border border-slate-600 hover:bg-slate-700/95',
        'secondary': 'bg-slate-900/95 text-cyan-100 border border-cyan-800/70 hover:bg-slate-800/95',
        'accent': 'bg-slate-900/95 text-violet-100 border border-violet-800/70 hover:bg-slate-800/95',
        'positive': 'bg-slate-900/95 text-emerald-100 border border-emerald-800/70 hover:bg-slate-800/95',
        'warning': 'bg-slate-900/95 text-amber-100 border border-amber-800/70 hover:bg-slate-800/95',
        'negative': 'bg-slate-900/95 text-rose-100 border border-rose-800/70 hover:bg-slate-800/95',
    }
    palette = button_classes.get(color, button_classes['primary'])
    return ui.button(label, on_click=on_click).props('unelevated no-caps').classes(
        f'rounded-xl px-4 py-2 font-semibold shadow-md shadow-black/25 transition duration-200 hover:-translate-y-0.5 {palette}'
    )


def clear_visible_mission_logs(trace_widgets: dict):
    clear_time = dt.datetime.now(dt.timezone.utc).isoformat()
    for service_name in SERVICE_URLS:
        MISSION_LOG_CLEAR_TIMES[service_name] = clear_time
        widget = trace_widgets.get(service_name)
        if widget is not None:
            widget.value = ''
            widget.update()
    ui.notify('Event panes cleared. New events will appear from this point onward.')


def scroll_textarea_to_bottom(area):
    async def _scroll():
        try:
            await ui.run_javascript(f'''
                requestAnimationFrame(() => {{
                    const element = getElement({area.id}).$refs.qRef.getNativeElement();
                    element.scrollTop = element.scrollHeight;
                }});
            ''', respond=False)
        except Exception:
            pass
    ui.timer(0.05, _scroll, once=True)


bob_resource_select = None
attacker_resource_select = None
dt_resource_select = None

live_bob_transaction = {
    'resource_id': '',
    'transaction_csr_pem': '',
    'binding_signature_b64': '',
    'transaction_certificate_pem': '',
    'cm_approval_payload': None,
    'cm_signature_b64': '',
    'cm_certificate_pem': '',
    'status': 'idle',
}


def reset_live_bob_transaction():
    live_bob_transaction.clear()
    live_bob_transaction.update({
        'resource_id': '',
        'transaction_csr_pem': '',
        'binding_signature_b64': '',
        'transaction_certificate_pem': '',
        'cm_approval_payload': None,
        'cm_signature_b64': '',
        'cm_certificate_pem': '',
        'status': 'idle',
    })


def public_live_bob_transaction():
    return dict(live_bob_transaction)


def sync_attacker_target_selects(resource_id: str):
    for widget in [attacker_resource_select, dt_resource_select]:
        if widget is None:
            continue
        if resource_id in getattr(widget, 'options', {}):
            widget.value = resource_id
            widget.update()


def fetch_resource_options():
    try:
        items = request_json('GET', f'{RM_URL}/api/v1/resources')
    except Exception:
        items = []
    return {
        item['resource_id']: f"{item['resource_id']} | {item['resource_name']}"
        for item in items
    }

def refresh_resource_select(select_widget):
    if select_widget is None:
        return
    options = fetch_resource_options()
    select_widget.options = options
    if getattr(select_widget, 'value', None) not in options:
        select_widget.value = None
    select_widget.update()

def pretty_json(value) -> str:
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return json.dumps(parsed, indent=2, sort_keys=True)
        except Exception:
            return value
    return json.dumps(value, indent=2, sort_keys=True)

def hero_banner(title: str, subtitle: str):
    with ui.column().classes('w-full gap-3 items-center'):
        ui.label(title).classes('w-full text-center text-5xl font-bold tracking-tight text-slate-50 drop-shadow-sm')
        ui.label(subtitle).classes('w-full max-w-6xl text-center text-lg font-medium leading-relaxed text-slate-300')

def section_card(title: str, subtitle: str = ""):
    card = ui.card().classes('w-full mx-auto rounded-2xl border border-slate-700/70 bg-slate-900/80 shadow-2xl shadow-black/35 backdrop-blur-sm transition duration-200 hover:-translate-y-0.5')
    with card:
        ui.label(title).classes('w-full text-center text-3xl font-bold text-cyan-100')
        if subtitle:
            ui.label(subtitle).classes('w-full text-center text-base text-slate-300')
    return card

class ArtifactBoard:
    def __init__(self, title: str):
        self.values = {}
        self.areas = {}
        self.card = ui.card().classes('w-full mx-auto rounded-2xl border border-slate-700/70 bg-slate-900/80 shadow-2xl shadow-black/35 backdrop-blur-sm transition duration-200 hover:-translate-y-0.5')
        with self.card:
            ui.label(title).classes('w-full text-center text-xl font-bold text-emerald-100')
            ui.label('Live artifacts and system outputs for this workspace appear below.').classes('w-full text-center text-sm text-slate-300')

    def add_area(self, key: str, label: str, editable: bool = False, rows: int = 5):
        with self.card:
            area = ui.textarea(label=label, value='', placeholder='Output').classes('w-full font-mono text-xs').style('text-align: left;')
            area.props('outlined rows=18 input-class=font-mono')
            if not editable:
                area.props('readonly')
            self.areas[key] = area
            self.values[key] = ''
            return area

    def set(self, key: str, value: str):
        self.values[key] = value
        if key in self.areas:
            area = self.areas[key]
            area.value = value
            scroll_textarea_to_bottom(area)

    def get(self, key: str) -> str:
        if key in self.areas:
            return self.areas[key].value or ''
        return self.values.get(key, '')

def service_status_strip():
    with ui.row().classes('w-full justify-center gap-3 flex-wrap'):
        for name, url in SERVICE_URLS.items():
            chip = ui.chip(f'{name}: checking...').props('outline').classes('border-slate-700 bg-slate-900/95 text-slate-100 shadow-sm shadow-black/20')
            def refresh(target=chip, service=name, service_url=url):
                try:
                    result = request_json('GET', f'{service_url}/api/v1/health')
                    target.text = f'{service}: {result["status"]}'
                except Exception:
                    target.text = f'{service}: down'
            ui.timer(2.5, refresh)

def generate_client_bundle(identity_email: str, cert_type: str):
    common_name = identity_email
    result = utils.generate_csr(cert_type=cert_type, common_name=common_name, sans=[identity_email])
    return result['csr_pem'], result['private_key_pem']

def sign_transaction_binding(transaction_csr_pem: str, session_private_key_pem: str) -> str:
    from cryptography.hazmat.primitives import serialization
    tx_csr = utils.load_pem_csr(transaction_csr_pem)
    tx_csr_der = tx_csr.public_bytes(serialization.Encoding.DER)
    private_key = AsymmetricCryptography.load_private_key(session_private_key_pem)
    signature = AsymmetricCryptography(private_key=private_key).sign(tx_csr_der)
    return base64.b64encode(signature).decode('utf-8')

def encrypt_resource_for_upload(resource_bytes: bytes, km_certificate_pem: str):
    utils.validate_certificate(km_certificate_pem, 'server', expected_identity=SERVICE_IDENTITIES['km'])
    sym = SymmetricCryptography()
    encrypted_resource = sym.encrypt(resource_bytes)
    km_public_key = utils.load_pem_certificate(km_certificate_pem).public_key()
    encrypted_data_key = AsymmetricCryptography(public_key=km_public_key).encrypt(sym.get_key())
    return {
        'symmetric_key_b64': utils.b64encode(sym.get_key()),
        'encrypted_resource_b64': utils.b64encode(encrypted_resource),
        'encrypted_data_key_b64': utils.b64encode(encrypted_data_key),
    }

def decrypt_download_bundle(transaction_private_key_pem: str, encrypted_resource_b64: str, re_encrypted_data_key_b64: str):
    transaction_private_key = AsymmetricCryptography.load_private_key(transaction_private_key_pem)
    symmetric_key = AsymmetricCryptography(private_key=transaction_private_key).decrypt(utils.b64decode(re_encrypted_data_key_b64))
    plaintext = SymmetricCryptography(key=symmetric_key).decrypt(utils.b64decode(encrypted_resource_b64))
    return {
        'decrypted_symmetric_key_b64': utils.b64encode(symmetric_key),
        'plaintext_utf8': plaintext.decode('utf-8', errors='replace'),
    }

def build_landing_links():
    with ui.row().classes('w-full justify-center gap-4 flex-wrap'):
        for title, subtitle in [
            ('Legitimate Flow Workspace', 'Run the core login, secure upload, consent-aware download and logout flows.'),
            ('Malicious Requester Workspace', 'Observe the replay-style attacks and their failure points.'),
            ('Malicious DT Workspace', 'Observe the post-consent certificate substitution attack and its failure points.'),
            ('Mission Control', 'Inspect live service health and event traces across the system.'),
        ]:
            with ui.card().classes('w-[320px] rounded-2xl border border-slate-700/70 bg-slate-900/80 shadow-xl shadow-black/30 transition duration-200 hover:-translate-y-0.5'):
                ui.label(title).classes('w-full text-center text-xl font-bold text-sky-100')
                ui.label(subtitle).classes('w-full text-center text-base text-slate-300')
                ui.label('Navigate using the tabs above.').classes('w-full text-center text-sm text-slate-400')

def index_page():
    ui.dark_mode().enable()
    hero_banner('Demo Prototype', 'Use the tabs above to move between the legitimate flow, malicious requester, malicious data trust and mission control workspaces within a single-window live demo. Each workspace presents the relevant state, artifacts and outcomes directly in the interface.\nThe prototype system supports simultaneous multi-actor role-play, making each flow and adversarial scenario directly observable.')
    service_status_strip()
    build_landing_links()

def workspace_frame(title: str, subtitle: str):
    hero_banner(title, subtitle)
    service_status_strip()
    return ui.column().classes('w-full gap-4')

def legitimate_workspace():
    ui.dark_mode().enable()
    workspace_frame(
        'Legitimate Flow Workspace',
        'Run the four core flows end to end while observing certificates, keys, resource representations, consent artifacts and revocation points directly in the interface.',
    )
    alice = {'access_token': '', 'session_certificate_pem': '', 'session_private_key_pem': '', 'last_resource_id': ''}
    bob = {'access_token': '', 'session_certificate_pem': '', 'session_private_key_pem': '', 'transaction_certificate_pem': '', 'transaction_private_key_pem': ''}

    with ui.row().classes(f'{PAGE_WIDTH} justify-center gap-6 items-start flex-wrap'):
        with ui.column().classes(COLUMN_WIDTH):
            with section_card('Alice: Login and Secure Upload', 'Alice acts as the legitimate Data Owner.'):
                alice_board = ArtifactBoard('Alice Artifact Console')
                alice_board.add_area('session_csr', 'Session CSR (Alice)', rows=4)
                alice_board.add_area('session_private_key', 'Session Private Key (Alice)', rows=5)
                alice_board.add_area('session_certificate', 'Session Certificate (Alice)', rows=8)
                alice_board.add_area('km_certificate', 'KM Certificate', rows=8)
                alice_board.add_area('plaintext_resource', 'Plaintext Resource', rows=4)
                alice_board.add_area('symmetric_key', 'Fresh Symmetric Data Key (Base64)', rows=3)
                alice_board.add_area('encrypted_resource', 'Encrypted Resource (Base64)', rows=4)
                alice_board.add_area('encrypted_data_key', 'Encrypted Data Key for KM (Base64)', rows=4)
                alice_board.add_area('rm_upload_response', 'RM Upload Response', rows=5)
                alice_board.add_area('cm_policy_response', 'CM Policy Registration Response', rows=4)

                resource_name_input = ui.input('Resource name', value='alice_demo_report.txt').classes('w-full max-w-[820px] mx-auto').style('text-align: left;')
                allowed_requesters_input = ui.input('Allowed requesters (comma separated emails)', value='bob@example.com').classes('w-full max-w-[820px] mx-auto').style('text-align: left;')
                resource_body_input = ui.textarea('Plaintext resource body', value='Alice confidential health report.\nOnly Bob should receive this after consent approval and key release.').classes('w-full max-w-[820px] mx-auto').style('text-align: left;').props('outlined rows=6')

                def alice_login():
                    try:
                        csr_pem, private_key_pem = generate_client_bundle('alice@example.com', 'client_session')
                        response = request_json('POST', f'{AAA_URL}/api/v1/login', json_body={
                            'username': 'alice',
                            'password': 'alice123',
                            'session_csr_pem': csr_pem,
                        })
                        alice['access_token'] = response['access_token']
                        alice['session_certificate_pem'] = response['session_certificate_pem']
                        alice['session_private_key_pem'] = private_key_pem
                        alice_board.set('session_csr', csr_pem)
                        alice_board.set('session_private_key', private_key_pem)
                        alice_board.set('session_certificate', response['session_certificate_pem'])
                        ui.notify('Alice logged in and received a session certificate.')
                    except Exception as exc:
                        ui.notify(f'Alice login failed: {exc}', color='negative')

                def alice_upload():
                    try:
                        if not alice['access_token']:
                            raise ValueError('Alice must log in first')
                        km_response = request_json('GET', f'{KM_URL}/api/v1/certificate')
                        encrypt_result = encrypt_resource_for_upload(resource_body_input.value.encode('utf-8'), km_response['km_certificate_pem'])
                        files = {
                            'encrypted_resource_file': (resource_name_input.value + '.enc', utils.b64decode(encrypt_result['encrypted_resource_b64']), 'application/octet-stream')
                        }
                        data = {
                            'access_token': alice['access_token'],
                            'owner_identity': 'alice@example.com',
                            'resource_name': resource_name_input.value,
                            'media_type': 'text/plain',
                            'encrypted_data_key_b64': encrypt_result['encrypted_data_key_b64'],
                        }
                        upload_response = request_json('POST', f'{RM_URL}/api/v1/upload', files=files, data=data)
                        policy_response = request_json('POST', f'{CM_URL}/api/v1/policies/upsert', json_body={
                            'resource_id': upload_response['resource_id'],
                            'owner_identity': 'alice@example.com',
                            'allowed_requesters': [item.strip() for item in allowed_requesters_input.value.split(',') if item.strip()],
                            'purpose': 'demo research evaluation',
                            'consent_version': 'v1',
                        })
                        alice['last_resource_id'] = upload_response['resource_id']
                        alice_board.set('km_certificate', km_response['km_certificate_pem'])
                        alice_board.set('plaintext_resource', resource_body_input.value)
                        alice_board.set('symmetric_key', encrypt_result['symmetric_key_b64'])
                        alice_board.set('encrypted_resource', encrypt_result['encrypted_resource_b64'])
                        alice_board.set('encrypted_data_key', encrypt_result['encrypted_data_key_b64'])
                        alice_board.set('rm_upload_response', pretty_json(upload_response))
                        alice_board.set('cm_policy_response', pretty_json(policy_response))
                        refresh_resource_select(bob_resource_select)
                        refresh_resource_select(attacker_resource_select)
                        refresh_resource_select(dt_resource_select)
                        ui.notify('Alice uploaded the encrypted resource and registered the consent policy.')
                    except Exception as exc:
                        ui.notify(f'Alice upload failed: {exc}', color='negative')

                def alice_logout():
                    try:
                        request_json('POST', f'{AAA_URL}/api/v1/logout', json_body={'access_token': alice['access_token'], 'session_certificate_pem': alice['session_certificate_pem']})
                        alice['access_token'] = ''
                        ui.notify('Alice logged out. The session certificate is now revoked.')
                    except Exception as exc:
                        ui.notify(f'Alice logout failed: {exc}', color='negative')

                with ui.row().classes(BUTTON_ROW):
                    action_button('1. Alice Login', on_click=alice_login, color='primary')
                    action_button('2. Encrypt & Upload', on_click=alice_upload, color='positive')
                    action_button('3. Alice Logout', on_click=alice_logout, color='warning')
                ui.separator()
                alice_board.card

        with ui.column().classes(COLUMN_WIDTH):
            with section_card('Bob: Consent-Aware Download and Logout', 'Bob acts as the legitimate Data Requester.'):
                bob_board = ArtifactBoard('Bob Artifact Console')
                bob_board.add_area('session_csr', 'Session CSR (Bob)', rows=4)
                bob_board.add_area('session_private_key', 'Session Private Key (Bob)', rows=5)
                bob_board.add_area('session_certificate', 'Session Certificate (Bob)', rows=8)
                bob_board.add_area('transaction_csr', 'Transaction CSR (Bob)', rows=4)
                bob_board.add_area('transaction_private_key', 'Transaction Private Key (Bob)', rows=5)
                bob_board.add_area('binding_signature', 'Signed Binding Object: Session-Key Signature over Transaction CSR (Base64)', rows=4)
                bob_board.add_area('transaction_certificate', 'Transaction Certificate (Bob)', rows=8)
                bob_board.add_area('transaction_status', 'Live Transaction Status', rows=4)
                bob_board.add_area('cm_approval_payload', 'CM Approval Payload', rows=6)
                bob_board.add_area('cm_signature', 'CM Approval Signature (Base64)', rows=4)
                bob_board.add_area('re_encrypted_data_key', 'Re-Encrypted Data Key for Bob (Base64)', rows=4)
                bob_board.add_area('decrypted_symmetric_key', 'Decrypted Symmetric Data Key (Base64)', rows=3)
                bob_board.add_area('plaintext_resource', 'Decrypted Plaintext Resource', rows=6)

                global bob_resource_select

                bob_resource_select = ui.select(options={}, label='Resource to download').classes('w-full max-w-[820px] mx-auto')
                refresh_resource_select(bob_resource_select)
                action_button('Refresh Resource List', on_click=lambda: refresh_resource_select(bob_resource_select), color='secondary')

                def bob_login():
                    try:
                        csr_pem, private_key_pem = generate_client_bundle('bob@example.com', 'client_session')
                        response = request_json('POST', f'{AAA_URL}/api/v1/login', json_body={
                            'username': 'bob',
                            'password': 'bob123',
                            'session_csr_pem': csr_pem,
                        })
                        bob['access_token'] = response['access_token']
                        bob['session_certificate_pem'] = response['session_certificate_pem']
                        bob['session_private_key_pem'] = private_key_pem
                        reset_live_bob_transaction()
                        bob_board.set('session_csr', csr_pem)
                        bob_board.set('session_private_key', private_key_pem)
                        bob_board.set('session_certificate', response['session_certificate_pem'])
                        bob_board.set('transaction_status', pretty_json(public_live_bob_transaction()))
                        ui.notify('Bob logged in and received a session certificate.')
                    except Exception as exc:
                        ui.notify(f'Bob login failed: {exc}', color='negative')

                def bob_issue_transaction_certificate():
                    try:
                        if not bob['session_private_key_pem']:
                            raise ValueError('Bob must log in first')
                        if not bob_resource_select.value:
                            raise ValueError('Choose a resource first')
                        tx_csr_pem, tx_private_key_pem = generate_client_bundle('bob@example.com', 'client_transaction')
                        binding_signature_b64 = sign_transaction_binding(tx_csr_pem, bob['session_private_key_pem'])
                        tx_issue_response = request_json('POST', f'{CA_URL}/api/v1/issue-transaction-certificate', json_body={
                            'session_certificate_pem': bob['session_certificate_pem'],
                            'transaction_csr_pem': tx_csr_pem,
                            'binding_signature_b64': binding_signature_b64,
                        })
                        bob['transaction_certificate_pem'] = tx_issue_response['certificate_pem']
                        bob['transaction_private_key_pem'] = tx_private_key_pem
                        reset_live_bob_transaction()
                        live_bob_transaction.update({
                            'resource_id': bob_resource_select.value,
                            'transaction_csr_pem': tx_csr_pem,
                            'binding_signature_b64': binding_signature_b64,
                            'transaction_certificate_pem': tx_issue_response['certificate_pem'],
                            'cm_approval_payload': None,
                            'cm_signature_b64': '',
                            'cm_certificate_pem': '',
                            'status': 'tx_cert_issued',
                        })
                        sync_attacker_target_selects(bob_resource_select.value)
                        bob_board.set('transaction_csr', tx_csr_pem)
                        bob_board.set('transaction_private_key', tx_private_key_pem)
                        bob_board.set('binding_signature', binding_signature_b64)
                        bob_board.set('transaction_certificate', tx_issue_response['certificate_pem'])
                        bob_board.set('cm_approval_payload', '')
                        bob_board.set('cm_signature', '')
                        bob_board.set('re_encrypted_data_key', '')
                        bob_board.set('decrypted_symmetric_key', '')
                        bob_board.set('plaintext_resource', '')
                        bob_board.set('transaction_status', pretty_json(public_live_bob_transaction()))
                        ui.notify('Bob issued a live transaction certificate for the selected resource.')
                    except Exception as exc:
                        ui.notify(f'Bob transaction issuance failed: {exc}', color='negative')

                def bob_request_cm_approval():
                    try:
                        if live_bob_transaction['status'] not in ['tx_cert_issued', 'cm_approved']:
                            raise ValueError('Bob must first issue a live transaction certificate')
                        approval = request_json('POST', f'{CM_URL}/api/v1/evaluate-consent', json_body={
                            'resource_id': live_bob_transaction['resource_id'],
                            'transaction_certificate_pem': live_bob_transaction['transaction_certificate_pem'],
                        })
                        live_bob_transaction['cm_approval_payload'] = approval['approval_payload']
                        live_bob_transaction['cm_signature_b64'] = approval['cm_signature_b64']
                        live_bob_transaction['cm_certificate_pem'] = approval['cm_certificate_pem']
                        live_bob_transaction['status'] = 'cm_approved'
                        bob_board.set('cm_approval_payload', pretty_json(approval['approval_payload']))
                        bob_board.set('cm_signature', approval['cm_signature_b64'])
                        bob_board.set('transaction_status', pretty_json(public_live_bob_transaction()))
                        ui.notify("CM approval is ready for Bob's live transaction.")
                    except Exception as exc:
                        ui.notify(f'Bob CM approval failed: {exc}', color='negative')

                def bob_complete_download():
                    try:
                        if live_bob_transaction['status'] != 'cm_approved':
                            raise ValueError('Bob must first issue a live transaction certificate and obtain CM approval')
                        encrypted_key = request_json('GET', f"{RM_URL}/api/v1/resources/{live_bob_transaction['resource_id']}/encrypted-key")
                        encrypted_resource = request_json('GET', f"{RM_URL}/api/v1/resources/{live_bob_transaction['resource_id']}/encrypted-resource")
                        km_response = request_json('POST', f'{KM_URL}/api/v1/release-data-key', json_body={
                            'resource_id': live_bob_transaction['resource_id'],
                            'transaction_certificate_pem': live_bob_transaction['transaction_certificate_pem'],
                            'cm_approval_payload': live_bob_transaction['cm_approval_payload'],
                            'cm_signature_b64': live_bob_transaction['cm_signature_b64'],
                            'cm_certificate_pem': live_bob_transaction['cm_certificate_pem'],
                            'encrypted_data_key_b64': encrypted_key['encrypted_data_key_b64'],
                        })
                        decrypt_result = decrypt_download_bundle(
                            bob['transaction_private_key_pem'],
                            encrypted_resource['encrypted_resource_b64'],
                            km_response['re_encrypted_data_key_b64'],
                        )
                        live_bob_transaction['status'] = 'completed'
                        bob_board.set('re_encrypted_data_key', km_response['re_encrypted_data_key_b64'])
                        bob_board.set('decrypted_symmetric_key', decrypt_result['decrypted_symmetric_key_b64'])
                        bob_board.set('plaintext_resource', decrypt_result['plaintext_utf8'])
                        bob_board.set('transaction_status', pretty_json(public_live_bob_transaction()))
                        ui.notify('Bob completed the download and the one-time transaction certificate has been revoked.')
                    except Exception as exc:
                        live_bob_transaction['status'] = 'failed'
                        bob_board.set('transaction_status', pretty_json(public_live_bob_transaction()))
                        ui.notify(f'Bob completion failed: {exc}', color='negative')

                def bob_logout():
                    try:
                        request_json('POST', f'{AAA_URL}/api/v1/logout', json_body={'access_token': bob['access_token'], 'session_certificate_pem': bob['session_certificate_pem']})
                        bob['access_token'] = ''
                        reset_live_bob_transaction()
                        bob_board.set('transaction_status', pretty_json(public_live_bob_transaction()))
                        ui.notify('Bob logged out. The session certificate is now revoked.')
                    except Exception as exc:
                        ui.notify(f'Bob logout failed: {exc}', color='negative')

                with ui.row().classes(BUTTON_ROW):
                    action_button('1. Bob Login', on_click=bob_login, color='primary')
                    action_button('2. Issue Transaction Certificate', on_click=bob_issue_transaction_certificate, color='info')
                    action_button('3. Request CM Approval', on_click=bob_request_cm_approval, color='secondary')
                    action_button('4. Complete Download', on_click=bob_complete_download, color='positive')
                    action_button('5. Bob Logout', on_click=bob_logout, color='warning')
                ui.separator()
                bob_board.card

def attacker_workspace():
    workspace_frame(
        'Malicious Requester Workspace',
        'Inspect two malicious requester attempts: invalid session-transaction binding and mid-flow replay of a valid live transaction certificate.',
    )
    mallory = {'access_token': '', 'session_cert': '', 'session_private_key': ''}

    with ui.row().classes(f'{PAGE_WIDTH} justify-center gap-6 items-start flex-wrap'):
        with ui.column().classes('w-full max-w-[1080px] gap-4'):
            with section_card('Malicious Requester Console', 'Mallory authenticates as herself but then tries to abuse Bob\'s artifacts.'):
                board = ArtifactBoard('Mallory Artifact Console')
                board.add_area('mallory_session_csr', 'Mallory Session CSR', rows=4)
                board.add_area('mallory_session_private_key', 'Mallory Session Private Key', rows=5)
                board.add_area('mallory_session_certificate', 'Mallory Session Certificate', rows=8)
                board.add_area('bob_session_certificate', 'Bob Session Certificate (Loaded for Replay)', editable=True, rows=8)
                board.add_area('forged_transaction_csr', 'Forged Transaction CSR (Bob identity, Mallory generated key)', rows=5)
                board.add_area('forged_binding_signature', 'Forged Binding Signature (Mallory session key)', rows=4)
                board.add_area('captured_transaction_bundle', 'Captured Bob Transaction Bundle', rows=10)
                board.add_area('live_bob_transaction', 'Live Bob Transaction Snapshot', rows=10)
                board.add_area('attack_result', 'Attack Result', rows=6)

                global attacker_resource_select

                attacker_resource_select = ui.select(options={}, label='Target resource for replay').classes('w-full max-w-[820px] mx-auto')
                refresh_resource_select(attacker_resource_select)
                action_button('Refresh Resource List', on_click=lambda: refresh_resource_select(attacker_resource_select), color='secondary')

                def mallory_login():
                    try:
                        csr_pem, private_key_pem = generate_client_bundle('mallory@example.com', 'client_session')
                        response = request_json('POST', f'{AAA_URL}/api/v1/login', json_body={
                            'username': 'mallory',
                            'password': 'mallory123',
                            'session_csr_pem': csr_pem,
                        })
                        mallory['access_token'] = response['access_token']
                        mallory['session_cert'] = response['session_certificate_pem']
                        mallory['session_private_key'] = private_key_pem
                        board.set('mallory_session_csr', csr_pem)
                        board.set('mallory_session_private_key', private_key_pem)
                        board.set('mallory_session_certificate', response['session_certificate_pem'])
                        ui.notify('Mallory logged in.')
                    except Exception as exc:
                        ui.notify(f'Mallory login failed: {exc}', color='negative')

                def load_bob_session():
                    try:
                        response = request_json('GET', f'{AAA_URL}/api/v1/demo/session/bob@example.com')
                        board.set('bob_session_certificate', response['session_certificate_pem'])
                        ui.notify("Bob's session certificate loaded.")
                    except Exception as exc:
                        ui.notify(f'Could not load Bob session certificate: {exc}', color='negative')

                def mallory_logout():
                    try:
                        request_json('POST', f'{AAA_URL}/api/v1/logout', json_body={'access_token': mallory['access_token'], 'session_certificate_pem': mallory['session_cert']})
                        mallory['access_token'] = ''
                        mallory['session_cert'] = ''
                        mallory['session_private_key'] = ''
                        ui.notify('Mallory logged out. The session certificate is now revoked.')
                    except Exception as exc:
                        ui.notify(f'Mallory logout failed: {exc}', color='negative')

                def load_live_bob_transaction():
                    try:
                        if live_bob_transaction['resource_id'] and attacker_resource_select is not None:
                            attacker_resource_select.value = live_bob_transaction['resource_id']
                            attacker_resource_select.update()
                        board.set('live_bob_transaction', pretty_json(public_live_bob_transaction()))
                        ui.notify('Live Bob transaction snapshot loaded.')
                    except Exception as exc:
                        ui.notify(f'Could not load live Bob transaction: {exc}', color='negative')

                def run_case_one():
                    try:
                        bob_session_cert = board.get('bob_session_certificate')
                        if not bob_session_cert:
                            raise ValueError('Load Bob session certificate first')
                        forged_csr_pem, _ = generate_client_bundle('bob@example.com', 'client_transaction')
                        forged_signature_b64 = sign_transaction_binding(forged_csr_pem, mallory['session_private_key'])
                        board.set('forged_transaction_csr', forged_csr_pem)
                        board.set('forged_binding_signature', forged_signature_b64)
                        try:
                            request_json('POST', f'{CA_URL}/api/v1/issue-transaction-certificate', json_body={
                                'session_certificate_pem': bob_session_cert,
                                'transaction_csr_pem': forged_csr_pem,
                                'binding_signature_b64': forged_signature_b64,
                            })
                            board.set('attack_result', 'Unexpected success: Transaction certificate issuance request was accepted.')
                        except Exception as exc:
                            board.set('attack_result', f'Transaction certificate issuance request was rejected as expected.\nReason: {exc}')
                        ui.notify('Case 1 request submitted.')
                    except Exception as exc:
                        ui.notify(f'Case 1 could not be executed: {exc}', color='negative')

                def run_case_two():
                    try:
                        if live_bob_transaction['status'] not in ['tx_cert_issued', 'cm_approved']:
                            raise ValueError('Bob must first issue a live transaction certificate and pause before completion')
                        resource_id = live_bob_transaction['resource_id']
                        if not resource_id:
                            raise ValueError('No live Bob transaction resource is available')
                        if attacker_resource_select.value and attacker_resource_select.value != resource_id:
                            raise ValueError('Mallory must target the same resource Bob is currently accessing')
                        if attacker_resource_select is not None:
                            attacker_resource_select.value = resource_id
                            attacker_resource_select.update()
                        board.set('captured_transaction_bundle', pretty_json(public_live_bob_transaction()))
                        board.set('live_bob_transaction', pretty_json(public_live_bob_transaction()))
                        download_response = request_json('POST', f'{RM_URL}/api/v1/download', json_body={
                            'resource_id': resource_id,
                            'transaction_certificate_pem': live_bob_transaction['transaction_certificate_pem'],
                        })
                        try:
                            decrypt_download_bundle(
                                mallory['session_private_key'],
                                download_response['encrypted_resource_b64'],
                                download_response['re_encrypted_data_key_b64'],
                            )
                            board.set('attack_result', 'Unexpected success: Key decryption completed.')
                        except Exception as exc:
                            live_bob_transaction['status'] = 'consumed_by_mallory'
                            board.set('live_bob_transaction', pretty_json(public_live_bob_transaction()))
                            board.set('attack_result', f'Key decryption failed as expected.\nReason: {exc}')
                        ui.notify("Case 2 executed against Bob's live transaction certificate.")
                    except Exception as exc:
                        ui.notify(f'Case 2 could not be executed: {exc}', color='negative')

                with ui.row().classes(BUTTON_ROW):
                    action_button('1. Mallory Login', on_click=mallory_login, color='negative')
                    action_button('2. Load Bob Session', on_click=load_bob_session, color='secondary')
                    action_button('3. Load Live Bob Transaction', on_click=load_live_bob_transaction, color='secondary')
                    action_button('4. Run Case 1', on_click=run_case_one, color='warning')
                    action_button('5. Run Case 2', on_click=run_case_two, color='negative')
                    action_button('6. Mallory Logout', on_click=mallory_logout, color='warning')
                board.card

def malicious_dt_workspace():
    ui.dark_mode().enable()
    workspace_frame(
        'Malicious DT Workspace',
        'Inspect malicious data trust attempt: certificate substitution after consent approval.',
    )
    with ui.row().classes(f'{PAGE_WIDTH} justify-center gap-6 items-start flex-wrap'):
        with ui.column().classes('w-full max-w-[1080px] gap-4'):
            with section_card('Malicious DT Console', "The malicious data trust intercepts Bob's live transaction and attempts certificate substitution after consent approval."):
                board = ArtifactBoard('Malicious DT Artifact Console')
                board.add_area('dt_session_csr', 'DT Session CSR', rows=4)
                board.add_area('dt_session_private_key', 'DT Session Private Key', rows=5)
                board.add_area('dt_session_certificate', 'DT Session Certificate', rows=8)
                board.add_area('dt_transaction_csr', 'DT Transaction CSR', rows=4)
                board.add_area('dt_binding_signature', 'DT Binding Signature (Base64)', rows=4)
                board.add_area('dt_transaction_certificate', 'DT Transaction Certificate', rows=8)
                board.add_area('bob_transaction_bundle', 'Captured Bob Transaction Bundle', rows=10)
                board.add_area('live_bob_transaction', 'Live Bob Transaction Snapshot', rows=10)
                board.add_area('bob_approval', 'CM Approval Bound to Bob Transaction Certificate', rows=8)
                board.add_area('attack_result', 'Attack Result', rows=6)

                dt_state = {'access_token': '', 'session_cert': '', 'session_key': ''}
                global dt_resource_select

                dt_resource_select = ui.select(options={}, label='Target resource for substitution').classes('w-full max-w-[820px] mx-auto')
                refresh_resource_select(dt_resource_select)
                action_button('Refresh Resource List', on_click=lambda: refresh_resource_select(dt_resource_select), color='secondary')

                def dt_login():
                    try:
                        csr_pem, private_key_pem = generate_client_bundle('dt@example.com', 'client_session')
                        response = request_json('POST', f'{AAA_URL}/api/v1/login', json_body={
                            'username': 'dt',
                            'password': 'dt123',
                            'session_csr_pem': csr_pem,
                        })
                        dt_state['access_token'] = response['access_token']
                        dt_state['session_cert'] = response['session_certificate_pem']
                        dt_state['session_key'] = private_key_pem
                        board.set('dt_session_csr', csr_pem)
                        board.set('dt_session_private_key', private_key_pem)
                        board.set('dt_session_certificate', response['session_certificate_pem'])
                        ui.notify('DT logged in.')
                    except Exception as exc:
                        ui.notify(f'DT login failed: {exc}', color='negative')

                def dt_logout():
                    try:
                        request_json('POST', f'{AAA_URL}/api/v1/logout', json_body={'access_token': dt_state['access_token'], 'session_certificate_pem': dt_state['session_cert']})
                        dt_state['access_token'] = ''
                        dt_state['session_cert'] = ''
                        dt_state['session_key'] = ''
                        ui.notify('DT logged out. The session certificate is now revoked.')
                    except Exception as exc:
                        ui.notify(f'DT logout failed: {exc}', color='negative')

                def load_live_bob_approved_transaction():
                    try:
                        if live_bob_transaction['resource_id'] and dt_resource_select is not None:
                            dt_resource_select.value = live_bob_transaction['resource_id']
                            dt_resource_select.update()
                        board.set('live_bob_transaction', pretty_json(public_live_bob_transaction()))
                        ui.notify('Live Bob transaction snapshot loaded.')
                    except Exception as exc:
                        ui.notify(f'Could not load live Bob transaction: {exc}', color='negative')

                def run_dt_substitution():
                    try:
                        if not dt_state['session_cert'] or not dt_state['session_key']:
                            raise ValueError('DT must log in first')
                        if live_bob_transaction['status'] != 'cm_approved':
                            raise ValueError('Bob must first obtain CM approval for a live transaction before DT can substitute certificates')
                        resource_id = live_bob_transaction['resource_id']
                        if not resource_id:
                            raise ValueError('No live Bob transaction resource is available')
                        if dt_resource_select.value and dt_resource_select.value != resource_id:
                            raise ValueError('DT must target the same resource Bob is currently accessing')
                        if dt_resource_select is not None:
                            dt_resource_select.value = resource_id
                            dt_resource_select.update()
                        dt_tx_csr_pem, _ = generate_client_bundle('dt@example.com', 'client_transaction')
                        dt_binding_b64 = sign_transaction_binding(dt_tx_csr_pem, dt_state['session_key'])
                        dt_tx_response = request_json('POST', f'{CA_URL}/api/v1/issue-transaction-certificate', json_body={
                            'session_certificate_pem': dt_state['session_cert'],
                            'transaction_csr_pem': dt_tx_csr_pem,
                            'binding_signature_b64': dt_binding_b64,
                        })
                        encrypted_key = request_json('GET', f'{RM_URL}/api/v1/resources/{resource_id}/encrypted-key')
                        board.set('bob_transaction_bundle', pretty_json(public_live_bob_transaction()))
                        board.set('live_bob_transaction', pretty_json(public_live_bob_transaction()))
                        board.set('bob_approval', pretty_json({
                            'approval_payload': live_bob_transaction['cm_approval_payload'],
                            'cm_signature_b64': live_bob_transaction['cm_signature_b64'],
                            'cm_certificate_pem': live_bob_transaction['cm_certificate_pem'],
                        }))
                        board.set('dt_transaction_csr', dt_tx_csr_pem)
                        board.set('dt_binding_signature', dt_binding_b64)
                        board.set('dt_transaction_certificate', dt_tx_response['certificate_pem'])
                        try:
                            request_json('POST', f'{KM_URL}/api/v1/release-data-key', json_body={
                                'resource_id': resource_id,
                                'transaction_certificate_pem': dt_tx_response['certificate_pem'],
                                'cm_approval_payload': live_bob_transaction['cm_approval_payload'],
                                'cm_signature_b64': live_bob_transaction['cm_signature_b64'],
                                'cm_certificate_pem': live_bob_transaction['cm_certificate_pem'],
                                'encrypted_data_key_b64': encrypted_key['encrypted_data_key_b64'],
                            })
                            board.set('attack_result', 'Unexpected success: Key release request was accepted.')
                        except Exception as exc:
                            board.set('attack_result', f'Key release request was rejected.\nReason: {exc}')
                        ui.notify("Malicious DT substitution executed against Bob's live CM-approved transaction.")
                    except Exception as exc:
                        ui.notify(f'DT substitution could not be executed: {exc}', color='negative')

                with ui.row().classes(BUTTON_ROW):
                    action_button('1. DT Login', on_click=dt_login, color='secondary')
                    action_button('2. Load Bob Approval', on_click=load_live_bob_approved_transaction, color='secondary')
                    action_button('3. Run Substitution Attack', on_click=run_dt_substitution, color='negative')
                    action_button('4. DT Logout', on_click=dt_logout, color='warning')
                board.card

def mission_control():
    ui.dark_mode().enable()
    hero_banner('Mission Control', 'Central live view of service health, event panes and outcomes across legitimate and adversarial flows.')
    service_status_strip()
    trace_widgets = {}

    with ui.row().classes('w-full justify-center gap-3 flex-wrap'):
        action_button('Clear Event Panes', on_click=lambda: clear_visible_mission_logs(trace_widgets), color='secondary')

    with ui.row().classes(f'{PAGE_WIDTH} justify-center gap-4 items-start flex-wrap'):
        for service_name, service_url in SERVICE_URLS.items():
            with ui.card().classes('w-full max-w-[500px] rounded-2xl border border-slate-700/80 bg-slate-950/90 shadow-xl shadow-black/30 backdrop-blur-sm transition duration-200 hover:-translate-y-0.5'):
                ui.label(service_name).classes('w-full text-center text-2xl font-bold text-slate-100')
                trace = ui.textarea(label=f'{service_name} event trace', value='').classes('w-full font-mono text-xs').style('text-align: left;').props('readonly outlined rows=24 input-class=font-mono')
                trace_widgets[service_name] = trace

                async def refresh_trace(target=trace, url=service_url, service_key=service_name):
                    try:
                        events = request_json('GET', f'{url}/api/v1/demo/events')
                        clear_time = MISSION_LOG_CLEAR_TIMES.get(service_key, '')
                        visible_events = [event for event in events if not clear_time or event.get('time_utc', '') > clear_time]
                        target.value = pretty_json(visible_events)
                    except Exception as exc:
                        target.value = f'Unable to fetch events: {exc}'
                    await ui.run_javascript(f'''
                        requestAnimationFrame(() => {{
                            const element = getElement({target.id}).$refs.qRef.getNativeElement();
                            element.scrollTop = element.scrollHeight;
                        }});
                    ''', respond=False)

                ui.timer(2.0, refresh_trace)


ui.add_head_html('''
<style>
  .demo-tab {
    border-radius: 0.85rem !important;
    background: rgba(10, 23, 51, 0.78) !important;
    border: 1px solid rgba(37, 99, 235, 0.18) !important;
    color: rgba(226, 232, 240, 0.72) !important;
    box-shadow: 0 6px 16px rgba(0, 0, 0, 0.20) !important;
    transition: transform 0.18s ease, background 0.18s ease, box-shadow 0.18s ease, color 0.18s ease, border-color 0.18s ease !important;
    min-height: 42px !important;
  }
  .demo-tab:hover {
    transform: translateY(-2px);
    background: rgba(15, 38, 84, 0.88) !important;
    color: rgba(248, 250, 252, 0.92) !important;
    border-color: rgba(59, 130, 246, 0.34) !important;
  }
  .demo-tab.q-tab--active {
    background: rgba(30, 64, 175, 0.96) !important;
    color: rgba(255, 255, 255, 1) !important;
    border-color: rgba(147, 197, 253, 0.60) !important;
    box-shadow: 0 10px 24px rgba(15, 23, 42, 0.38), inset 0 1px 0 rgba(255,255,255,0.08) !important;
  }
  .demo-tab .q-tab__label {
    font-weight: 600 !important;
    letter-spacing: 0.01em !important;
  }
  .q-tab__indicator,
  .q-tabs__content .q-tab__indicator,
  .q-tab--active .q-tab__indicator,
  .q-focus-helper {
    display: none !important;
    opacity: 0 !important;
    visibility: hidden !important;
    height: 0 !important;
    width: 0 !important;
  }
  .q-tab--inactive {
    opacity: 1 !important;
  }
</style>
''')

ui.dark_mode().enable()
with ui.header().classes('w-full justify-center bg-slate-950/92 border-b border-slate-800/90 backdrop-blur-sm shadow-lg shadow-black/25'):
    with ui.column().classes('w-full items-center gap-2 py-2'):
        ui.label('Automated Trust Enforcement in Consent-Driven Data Trust Platforms').classes('text-4xl font-bold text-slate-50 tracking-tight')
        with ui.tabs().classes('w-full max-w-6xl mx-auto justify-center gap-3 py-1') as tabs:
            tab_home = ui.tab('Home').classes('demo-tab mx-1 px-5')
            tab_legit = ui.tab('Legitimate Flow').classes('demo-tab mx-1 px-5')
            tab_attacker = ui.tab('Malicious Requester').classes('demo-tab mx-1 px-5')
            tab_dt = ui.tab('Malicious DT').classes('demo-tab mx-1 px-5')
            tab_mc = ui.tab('Mission Control').classes('demo-tab mx-1 px-5')
with ui.tab_panels(tabs, value=tab_home).classes('w-full max-w-[1700px] mx-auto pt-28'):
    with ui.tab_panel(tab_home):
        with ui.column().classes(f'{PAGE_WIDTH} items-center gap-6 px-4 py-4'):
            index_page()
    with ui.tab_panel(tab_legit):
        with ui.column().classes(f'{PAGE_WIDTH} items-center gap-6 px-4 py-4'):
            legitimate_workspace()
    with ui.tab_panel(tab_attacker):
        with ui.column().classes(f'{PAGE_WIDTH} items-center gap-6 px-4 py-4'):
            attacker_workspace()
    with ui.tab_panel(tab_dt):
        with ui.column().classes(f'{PAGE_WIDTH} items-center gap-6 px-4 py-4'):
            malicious_dt_workspace()
    with ui.tab_panel(tab_mc):
        with ui.column().classes(f'{PAGE_WIDTH} items-center gap-6 px-4 py-4'):
            mission_control()

ui.run(
    title='Demo Frontend',
    reload=False,
    native=False,
    port=FRONTEND_PORT,
    host='0.0.0.0',
    favicon='🔐',
    show=False,
    dark=True,
)
