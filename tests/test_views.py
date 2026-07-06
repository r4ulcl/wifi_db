from unittest import mock

from test_base import DBTestBase, sample_cert
from utils import database_utils
from utils import wifi_db_aircrack


class TestViews(DBTestBase):
    def test_insertCertificate(self):
        # Define a parsed certificate (as built by _extract_cert_fields)
        cert = sample_cert()

        # Insert new certificate (AP/server certificate)
        result = database_utils.insertCertificate(self.c, self.verbose,
                                                  self.bssid, self.mac,
                                                  'AP', 'test.cap', cert)
        self.assertEqual(result, 0)

        self.c.execute("SELECT subject_cn, issuer_cn, cert_type, "
                       "subject_alt_names, ext_key_usage, self_signed, "
                       "validity_days, public_key_exponent, "
                       "sha256_fingerprint "
                       "FROM Certificate WHERE bssid = ?", (self.bssid,))
        rows = self.c.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], cert['subject_cn'])
        self.assertEqual(rows[0][1], cert['issuer_cn'])
        self.assertEqual(rows[0][2], 'AP')
        self.assertEqual(rows[0][3], cert['subject_alt_names'])
        self.assertEqual(rows[0][4], cert['ext_key_usage'])
        self.assertEqual(rows[0][5], cert['self_signed'])
        self.assertEqual(rows[0][6], cert['validity_days'])
        self.assertEqual(rows[0][7], cert['public_key_exponent'])
        self.assertEqual(rows[0][8], cert['sha256_fingerprint'])

        # A client certificate (different fingerprint) is stored in the same
        # table for the same AP, tagged with its own cert_type
        client_cert = dict(cert)
        client_cert['sha256_fingerprint'] = '99ff88ee77dd'
        client_cert['subject_cn'] = 'user.test.local'
        result = database_utils.insertCertificate(self.c, self.verbose,
                                                  self.bssid, self.mac,
                                                  'Client', 'test.cap',
                                                  client_cert)
        self.assertEqual(result, 0)
        self.c.execute("SELECT cert_type FROM Certificate WHERE bssid = ? "
                       "ORDER BY cert_type", (self.bssid,))
        self.assertEqual([r[0] for r in self.c.fetchall()], ['AP', 'Client'])

        # Inserting the same certificate again must not duplicate it
        result = database_utils.insertCertificate(self.c, self.verbose,
                                                  self.bssid, self.mac,
                                                  'AP', 'test.cap', cert)
        self.assertEqual(result, 0)
        self.c.execute("SELECT COUNT(*) FROM Certificate WHERE bssid = ?",
                       (self.bssid,))
        self.assertEqual(self.c.fetchone()[0], 2)

    def test_parse_certificates(self):
        # Regression: EAP-TLS certificates are reassembled by tshark across
        # EAPOL fragments, which pyshark's display-filter iteration never
        # surfaced, so the Certificate table stayed empty. parse_certificates
        # now reads tshark -T fields output directly; mock that output (with a
        # real cert chain + a client cert) and check the rows are stored.
        ap, sta = "F0:9F:C2:71:22:14", "28:6C:07:6F:F9:44"
        server = self._make_cert_hex(u"radius.contoso.local")
        ca = self._make_cert_hex(u"Contoso Root CA")
        client = self._make_cert_hex(u"user@contoso")

        # Columns: tls.handshake.certificate \t wlan.sa \t wlan.da \t eap.code.
        # A chain is comma-joined in a single column; eap.code 1 = AP/server,
        # 2 = client.
        line_ap = "\t".join([server + "," + ca, ap, sta, "1"])
        line_client = "\t".join([client, sta, ap, "2"])
        fake_stdout = (line_ap + "\n" + line_client + "\n").encode("utf-8")
        fake = mock.Mock()
        fake.stdout = fake_stdout

        with mock.patch("utils.cert_parsers.subprocess.run",
                        return_value=fake):
            wifi_db_aircrack.parse_certificates("scanc44-01.cap",
                                                self.database, self.verbose)

        rows = self.c.execute(
            "SELECT bssid, mac, cert_type, subject_cn, cert_index "
            "FROM Certificate ORDER BY cert_type, cert_index").fetchall()
        # 2 certs in the AP chain + 1 client cert
        self.assertEqual(len(rows), 3)
        self.assertEqual([r[2] for r in rows], ['AP', 'AP', 'Client'])
        # AP chain keeps its order via cert_index
        self.assertEqual(rows[0][3], 'radius.contoso.local')
        self.assertEqual(rows[0][4], 0)
        self.assertEqual(rows[1][3], 'Contoso Root CA')
        self.assertEqual(rows[1][4], 1)
        # Whoever sent the cert, the BSSID stored is always the AP and the MAC
        # the client.
        for row in rows:
            self.assertEqual(row[0], ap)
            self.assertEqual(row[1], sta)

    def test_insertSecurity(self):
        # Insert RSN/WPA security details for an AP (WPA3-Enterprise)
        result = database_utils.insertSecurity(
            self.c, self.verbose, database_utils.SecurityRow(
                bssid=self.bssid, wpa_version='WPA3',
                akm_suites='802.1X-SuiteB-SHA384', pairwise_ciphers='GCMP-256',
                group_cipher='GCMP-256', enterprise='True', pmf='Required',
                rsn_capabilities='0x00c0', file='test.cap'))
        self.assertEqual(result, 0)

        # Security columns now live on the AP row (1:1 merge)
        self.c.execute("SELECT wpa_version, akm_suites, pairwise_ciphers, "
                       "enterprise, pmf FROM AP WHERE bssid = ?",
                       (self.bssid,))
        rows = self.c.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], 'WPA3')
        self.assertEqual(rows[0][1], '802.1X-SuiteB-SHA384')
        self.assertEqual(rows[0][2], 'GCMP-256')
        self.assertEqual(rows[0][3], 'True')
        self.assertEqual(rows[0][4], 'Required')

        # A second beacon for the same BSSID overwrites the AP columns
        result = database_utils.insertSecurity(
            self.c, self.verbose, database_utils.SecurityRow(
                bssid=self.bssid, wpa_version='WPA2', akm_suites='PSK',
                pairwise_ciphers='CCMP-128', group_cipher='CCMP-128',
                enterprise='False', pmf='Capable', rsn_capabilities='0x0080',
                file='test.cap'))
        self.assertEqual(result, 0)
        self.c.execute("SELECT COUNT(*), MAX(wpa_version) FROM AP "
                       "WHERE bssid = ?", (self.bssid,))
        count, wpa_version = self.c.fetchone()
        self.assertEqual(count, 1)
        self.assertEqual(wpa_version, 'WPA2')

    def test_security_and_certificate_views(self):
        # The SecurityAP and CertificateAP views must join Security/Certificate
        # to AP on the BSSID and expose the expected columns.
        database_utils.insertSecurity(
            self.c, self.verbose, database_utils.SecurityRow(
                bssid=self.bssid, wpa_version='WPA3', akm_suites='SAE',
                pairwise_ciphers='CCMP-128', group_cipher='CCMP-128',
                enterprise='False', pmf='Required', rsn_capabilities='0x00c0',
                file='test.cap'))
        self.c.execute("SELECT wpa_version, pmf FROM SecurityAP "
                       "WHERE bssid = ?", (self.bssid,))
        row = self.c.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], 'WPA3')
        self.assertEqual(row[1], 'Required')

        cert = {
            'cert_index': 0, 'version': 'v3', 'serial_number': 'ab',
            'signature_algorithm': 'sha256WithRSAEncryption',
            'issuer': 'CN=CA', 'subject': 'CN=radius',
            'not_before': '', 'not_after': '', 'subject_cn': 'radius',
            'subject_o': '', 'subject_ou': '', 'issuer_cn': 'CA',
            'issuer_o': '', 'issuer_ou': '', 'public_key_algorithm': 'RSA',
            'public_key_size': 2048, 'public_key_curve': '',
            'public_key_exponent': '65537', 'subject_alt_names': '',
            'key_usage': '', 'ext_key_usage': '', 'is_ca': 'False',
            'path_length': None, 'self_signed': 'False',
            'authority_key_id': '', 'subject_key_id': '', 'crl_urls': '',
            'ocsp_urls': '', 'validity_days': 365,
            'sha1_fingerprint': 'aa', 'sha256_fingerprint': 'viewfp',
        }
        database_utils.insertCertificate(self.c, self.verbose, self.bssid,
                                         self.mac, 'AP', 'test.cap', cert)
        self.c.execute("SELECT cert_type, subject_cn FROM CertificateAP "
                       "WHERE bssid = ?", (self.bssid,))
        row = self.c.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], 'AP')
        self.assertEqual(row[1], 'radius')

    def test_insertCapabilities(self):
        # Store 802.11r/k/v + MBSSID + CSA capabilities on the AP row.
        result = database_utils.insertCapabilities(
            self.c, self.verbose, database_utils.CapabilitiesRow(
                bssid=self.bssid, ft_80211r='True', mobility_domain_id='0xabcd',
                rrm_80211k='True', bss_transition_80211v='True', mbssid='True',
                max_bssid_indicator=8, csa='True', csa_new_channel=36))
        self.assertEqual(result, 0)
        self.c.execute("SELECT ft_80211r, mobility_domain_id, rrm_80211k, "
                       "bss_transition_80211v, mbssid, max_bssid_indicator, "
                       "csa, csa_new_channel FROM AP WHERE bssid = ?",
                       (self.bssid,))
        row = self.c.fetchone()
        self.assertEqual(row, ('True', '0xabcd', 'True', 'True', 'True', 8,
                               'True', 36))

        # A later beacon without the elements must NOT clear sticky flags, and
        # must keep the detail fields it does not carry.
        result = database_utils.insertCapabilities(
            self.c, self.verbose, database_utils.CapabilitiesRow(
                bssid=self.bssid, ft_80211r='False', mobility_domain_id='',
                rrm_80211k='False', bss_transition_80211v='False',
                mbssid='False', max_bssid_indicator=None, csa='False',
                csa_new_channel=None))
        self.assertEqual(result, 0)
        self.c.execute("SELECT ft_80211r, mobility_domain_id, rrm_80211k, "
                       "csa_new_channel FROM AP WHERE bssid = ?",
                       (self.bssid,))
        row = self.c.fetchone()
        self.assertEqual(row, ('True', '0xabcd', 'True', 36))

    def test_cloaked_sticky_on_merge(self):
        # A detected cloaked='True' must survive later merges (e.g. a beacon
        # enriching the AP via insertAPConstraint, which passes 'False').
        database_utils.insertAP(
            self.c, self.verbose, database_utils.APRow(
                bssid=self.bssid, essid="", manuf="manuf", channel="6",
                freqmhz="2437", carrier="", encryption="WPA2",
                packets_total="0", lat="0.0", lon="0.0", cloaked='True',
                mfpc='False', mfpr='False', firstTimeSeen=0))
        database_utils.insertSecurity(
            self.c, self.verbose, database_utils.SecurityRow(
                bssid=self.bssid, wpa_version='WPA2', akm_suites='PSK',
                pairwise_ciphers='CCMP-128', group_cipher='CCMP-128',
                enterprise='False', pmf='Disabled', rsn_capabilities='0x0000',
                file='test.cap'))
        self.c.execute("SELECT cloaked FROM AP WHERE bssid = ?", (self.bssid,))
        self.assertEqual(self.c.fetchone()[0], 'True')

    def test_insertHiddenSSID(self):
        # An AP with no SSID yet gets its name filled and flagged as revealed.
        database_utils.insertAPConstraint(self.c, self.verbose, self.bssid)
        result = database_utils.insertHiddenSSID(
            self.c, self.verbose, self.bssid, "RecoveredNet")
        self.assertEqual(result, 0)
        self.c.execute("SELECT ssid, ssid_revealed FROM AP WHERE bssid = ?",
                       (self.bssid,))
        self.assertEqual(self.c.fetchone(), ("RecoveredNet", 'True'))

        # A known SSID must never be overwritten by a reveal.
        result = database_utils.insertHiddenSSID(
            self.c, self.verbose, self.bssid, "DifferentName")
        self.assertEqual(result, 0)
        self.c.execute("SELECT ssid FROM AP WHERE bssid = ?", (self.bssid,))
        self.assertEqual(self.c.fetchone()[0], "RecoveredNet")

    def test_capabilities_view(self):
        # The CapabilitiesAP view exposes the capability columns from AP and
        # only lists APs that advertise at least one of them.
        database_utils.insertCapabilities(
            self.c, self.verbose, database_utils.CapabilitiesRow(
                bssid=self.bssid, ft_80211r='True', mobility_domain_id='0x1234',
                rrm_80211k='False', bss_transition_80211v='False',
                mbssid='False', max_bssid_indicator=None, csa='False',
                csa_new_channel=None))
        self.c.execute("SELECT ssid, ft_80211r, mobility_domain_id "
                       "FROM CapabilitiesAP WHERE bssid = ?", (self.bssid,))
        row = self.c.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[1], 'True')
        self.assertEqual(row[2], '0x1234')

        # An AP with no capabilities advertised must not appear in the view.
        other = "AA:BB:CC:DD:EE:FF"
        database_utils.insertAPConstraint(self.c, self.verbose, other)
        self.c.execute("SELECT COUNT(*) FROM CapabilitiesAP WHERE bssid = ?",
                       (other,))
        self.assertEqual(self.c.fetchone()[0], 0)

    def test_rsn_capabilities_text(self):
        # 1.6: insertSecurity decodes the raw rsn_capabilities bitmask into the
        # sibling rsn_capabilities_text column, exposed via SecurityAP.
        database_utils.insertSecurity(
            self.c, self.verbose, database_utils.SecurityRow(
                bssid=self.bssid, wpa_version='WPA2', akm_suites='PSK',
                pairwise_ciphers='CCMP-128', group_cipher='CCMP-128',
                enterprise='False', pmf='Required', rsn_capabilities='0x00c0',
                file='test.cap'))
        self.c.execute("SELECT rsn_capabilities, rsn_capabilities_text "
                       "FROM AP WHERE bssid = ?", (self.bssid,))
        self.assertEqual(self.c.fetchone(), ('0x00c0', 'MFPR, MFPC'))
        self.c.execute("SELECT rsn_capabilities_text FROM SecurityAP "
                       "WHERE bssid = ?", (self.bssid,))
        self.assertEqual(self.c.fetchone()[0], 'MFPR, MFPC')

        # An empty/zero bitmask decodes to '' rather than a bogus flag list.
        other = "AA:BB:CC:DD:EE:01"
        database_utils.insertSecurity(
            self.c, self.verbose, database_utils.SecurityRow(
                bssid=other, wpa_version='WPA2', akm_suites='PSK',
                pairwise_ciphers='CCMP-128', group_cipher='CCMP-128',
                enterprise='False', pmf='Disabled', rsn_capabilities='0x0000',
                file='test.cap'))
        self.c.execute("SELECT rsn_capabilities_text FROM AP WHERE bssid = ?",
                       (other,))
        self.assertEqual(self.c.fetchone()[0], '')

    def test_summary_view(self):
        # 1.6: SummaryAP groups by SSID *and* encryption, counting APs and
        # connected clients and concatenating the distinct wpa_version, pmf and
        # manuf seen per group.
        ap2 = "AA:BB:CC:DD:EE:02"
        # Two WPA2 APs sharing one SSID, different manufacturers.
        self.insert_test_ap(essid="Corp", encryption="WPA2",
                            manuf="VendorA")
        database_utils.insertAP(
            self.c, self.verbose, database_utils.APRow(
                bssid=ap2, essid="Corp", manuf="VendorB", channel="11",
                freqmhz="2462", carrier="", encryption="WPA2",
                packets_total="5", lat="0.0", lon="0.0", cloaked='False',
                mfpc='False', mfpr='False', firstTimeSeen=0))
        for bssid in (self.bssid, ap2):
            database_utils.insertSecurity(
                self.c, self.verbose, database_utils.SecurityRow(
                    bssid=bssid, wpa_version='WPA2', akm_suites='PSK',
                    pairwise_ciphers='CCMP-128', group_cipher='CCMP-128',
                    enterprise='False', pmf='Capable',
                    rsn_capabilities='0x0080', file='test.cap'))
        # One client connected to the first AP.
        self.insert_test_client()
        database_utils.insertConnected(self.c, self.verbose, self.bssid,
                                       self.mac)
        # A same-SSID AP with a *different* encryption forms its own group.
        database_utils.insertAP(
            self.c, self.verbose, database_utils.APRow(
                bssid="AA:BB:CC:DD:EE:03", essid="Corp", manuf="VendorC",
                channel="36", freqmhz="5180", carrier="", encryption="WPA3",
                packets_total="1", lat="0.0", lon="0.0", cloaked='False',
                mfpc='False', mfpr='False', firstTimeSeen=0))

        self.c.execute(
            'SELECT "APs count", wpa_version, pmf, manuf, "Clients count" '
            'FROM SummaryAP WHERE ssid = ? AND encryption = ?',
            ("Corp", "WPA2"))
        aps_count, wpa_version, pmf, manuf, clients_count = self.c.fetchone()
        self.assertEqual(aps_count, 2)
        self.assertEqual(wpa_version, 'WPA2')
        self.assertEqual(pmf, 'Capable')
        self.assertIn('VendorA', manuf)
        self.assertIn('VendorB', manuf)
        self.assertEqual(clients_count, 1)

        # The WPA3 AP is a separate group, so "Corp" spans two rows.
        self.c.execute("SELECT COUNT(*) FROM SummaryAP WHERE ssid = ?",
                       ("Corp",))
        self.assertEqual(self.c.fetchone()[0], 2)

