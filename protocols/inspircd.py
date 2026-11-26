"""
inspircd.py: InspIRCd 2.0, 3.x, 4.x protocol module for PyLink.
"""

import threading
import time

from pylinkirc import conf
from pylinkirc.classes import *
from pylinkirc.log import log
from pylinkirc.protocols.ts6_common import TS6BaseProtocol

__all__ = ['InspIRCdProtocol']

# Mapeamento de nomes de extbans do InspIRCd 4 (CAPAB EXTBANS) para nomes internos do PyLink
INSP4_ACTING_EXTBAN_MAP = {
    'mute': 'quiet',
    'quiet': 'quiet',
    'nickchange': 'ban_nonick',
    'nonick': 'ban_nonick',
    'blockcolor': 'ban_blockcolor',
    'partmsg': 'ban_partmsgs',
    'invite': 'ban_invites',
    'anticaps': 'ban_blockcaps',
    'blockcaps': 'ban_blockcaps',
    'noctcp': 'ban_noctcp',
    'nokick': 'ban_nokicks',
    'stripcolor': 'ban_stripcolor',
    'nonotice': 'ban_nonotice',
}

INSP4_MATCHING_EXTBAN_MAP = {
    'channel': 'ban_inchannel',
    'realname': 'ban_realname',
    'server': 'ban_server',
    'fingerprint': 'ban_certfp',
    'opertype': 'ban_opertype',
    'account': 'ban_account',
    'unregistered': 'ban_unregistered_matching',
}


class InspIRCdProtocol(TS6BaseProtocol):

    S2S_BUFSIZE = 0  # InspIRCd allows infinitely long S2S messages, so set bufsize to infinite
    SUPPORTED_IRCDS = ['insp20', 'insp3', 'insp4']
    DEFAULT_IRCD = SUPPORTED_IRCDS[1]

    MAX_PROTO_VER = 1206  # anything above this warns (not officially supported)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.protocol_caps |= {'slash-in-nicks', 'slash-in-hosts', 'underscore-in-hosts'}

        # Raw commands sent from servers vary from protocol to protocol. Here, we map
        # non-standard names to our hook handlers, so command handlers' outputs
        # are called with the right hooks.
        self.hook_map = {'FJOIN': 'JOIN', 'RSQUIT': 'SQUIT', 'FMODE': 'MODE',
                         'LMODE': 'MODE', 'FTOPIC': 'TOPIC', 'OPERTYPE': 'MODE',
                         'FHOST': 'CHGHOST', 'FIDENT': 'CHGIDENT', 'FNAME': 'CHGNAME',
                         'SVSTOPIC': 'TOPIC', 'SAKICK': 'KICK', 'IJOIN': 'JOIN'}

        ircd_target = self.serverdata.get('target_version', self.DEFAULT_IRCD).lower()
        if ircd_target == 'insp20':
            self.proto_ver = 1202
        elif ircd_target == 'insp3':
            self.proto_ver = 1205
        elif ircd_target == 'insp4':
            self.proto_ver = 1206
        else:
            raise ProtocolError("Unsupported target_version %r: supported values include %s" %
                                (ircd_target, self.SUPPORTED_IRCDS))
        log.debug('(%s) inspircd: using protocol version %s for target_version %r',
                  self.name, self.proto_ver, ircd_target)

    def _init_vars(self, *args, **kwargs):
        super()._init_vars(*args, **kwargs)

        # Default casemapping - on InspIRCd 3/4 this is negotiated via CAPAB CAPABILITIES
        self.casemapping = 'rfc1459'

        # Remote protocol version reported in CAPAB START
        self.remote_proto_ver = None

        # Tracks whether our CAPAB/SERVER/BURST handshake was already sent
        self._handshake_sent = False

        # Track prefix mode levels on InspIRCd 3/4
        self._prefix_levels = {}

        # Track the modules supported by the uplink
        self._modsupport = set()

        # Settable by plugins (e.g. relay) as needed, used to work around +j being triggered
        # by bursting users.
        self._endburst_delay = 0

        # Default extban definitions (may be updated dynamically by CAPAB EXTBANS on InspIRCd 4)
        self.extbans_acting = {
            'quiet': 'm:', 'ban_nonick': 'N:', 'ban_blockcolor': 'c:',
            'ban_partmsgs': 'p:', 'ban_invites': 'A:', 'ban_blockcaps': 'B:',
            'ban_noctcp': 'C:', 'ban_nokicks': 'Q:', 'ban_stripcolor': 'S:',
            'ban_nonotice': 'T:',
        }
        self.extbans_matching = {
            'ban_inchannel': 'j:', 'ban_realname': 'r:', 'ban_server': 's:',
            'ban_certfp': 'z:', 'ban_opertype': 'O:', 'ban_account': 'R:',
            # Note: InspIRCd /helpop refers to this as an acting extban, but
            # it actually behaves as a matching one...
            'ban_unregistered_matching': 'U:',
        }

    @property
    def negotiated_proto_ver(self):
        """Returns the effective negotiated protocol version (minimum of local and remote)."""
        if self.remote_proto_ver is None:
            return self.proto_ver
        return min(self.proto_ver, self.remote_proto_ver)

    def handle_events(self, line):
        """Strips IRCv3 message tags (used natively in InspIRCd 4 / protocol 1206) before parsing."""
        if line.startswith('@'):
            parts = line.split(' ', 1)
            if len(parts) < 2:
                log.debug('(%s) inspircd: ignoring tag-only line: %r', self.name, line)
                return
            line = parts[1].lstrip(' ')
        return super().handle_events(line)

    def _normalize_module_name(self, module):
        """Normalizes InspIRCd module names across protocol versions."""
        if not module:
            return ''

        module = module.split('=', 1)[0].lower()
        if module.startswith('m_'):
            module = module[2:]
        if module.endswith('.so'):
            module = module[:-3]
        return module

    def _add_module_support(self, module):
        module = self._normalize_module_name(module)
        if module:
            self._modsupport.add(module)

    def _remove_module_support(self, module):
        module = self._normalize_module_name(module)
        if module:
            self._modsupport.discard(module)

    def _has_module(self, module):
        return self._normalize_module_name(module) in self._modsupport

    ### Outgoing commands

    def spawn_client(self, nick, ident='null', host='null', realhost=None, modes=set(),
            server=None, ip='0.0.0.0', realname=None, ts=None, opertype='IRC Operator',
            manipulatable=False):
        """
        Spawns a new client with the given options.

        Note: No nick collision / valid nickname checks are done here; it is
        up to plugins to make sure they don't introduce anything invalid.
        """
        server = server or self.sid

        if not self.is_internal_server(server):
            raise ValueError('Server %r is not a PyLink server!' % server)

        uid = self.uidgen[server].next_uid()

        ts = ts or int(time.time())
        realname = realname or conf.conf['pylink']['realname']
        realhost = realhost or host
        raw_modes = self.join_modes(modes)
        u = self.users[uid] = User(self, nick, ts, uid, server, ident=ident, host=host,
                                   realname=realname, realhost=realhost, ip=ip,
                                   manipulatable=manipulatable, opertype=opertype)
        u.realident = ident

        self.apply_modes(uid, modes)
        self.servers[server].users.add(uid)

        if self.negotiated_proto_ver >= 1206:
            # InspIRCd 4 (1206):
            # :<sid> UID <uid> <age> <nick> <realhost> <dhost> <realuser> <duser> <ip> <signon> <modes> [<params>...] :<realname>
            payload = ("UID {uid} {ts} {nick} {realhost} {host} {realident} {ident} {ip}"
                       " {ts} {modes} :{realname}").format(ts=ts, host=host,
                       nick=nick, ident=ident, uid=uid, realident=ident,
                       modes=raw_modes, ip=ip, realname=realname,
                       realhost=realhost)
        else:
            # InspIRCd 2/3 (1202/1205):
            # :<sid> UID <uid> <age> <nick> <realhost> <dhost> <duser> <ip> <signon> <modes> [<params>...] :<realname>
            payload = ("UID {uid} {ts} {nick} {realhost} {host} {ident} {ip}"
                       " {ts} {modes} :{realname}").format(ts=ts, host=host,
                       nick=nick, ident=ident, uid=uid,
                       modes=raw_modes, ip=ip, realname=realname,
                       realhost=realhost)
        self._send_with_prefix(server, payload)
        if ('o', None) in modes or ('+o', None) in modes:
            self._oper_up(uid, opertype)
        return u

    def join(self, client, channel):
        """Joins a PyLink client to a channel."""
        # InspIRCd doesn't distinguish between burst joins and regular joins,
        # so what we're actually doing here is sending FJOIN from the server,
        # on behalf of the clients that are joining.

        server = self.get_server(client)
        if not self.is_internal_server(server):
            log.error('(%s) Error trying to join %r to %r (no such client exists)', self.name, client, channel)
            raise LookupError('No such PyLink client exists.')

        # Strip out list-modes, they shouldn't be ever sent in FJOIN.
        modes = [m for m in self._channels[channel].modes if m[0][-1] not in self.cmodes['*A']]
        self._send_with_prefix(server, "FJOIN {channel} {ts} {modes} :,{uid}".format(
                ts=self._channels[channel].ts, uid=client, channel=channel,
                modes=self.join_modes(modes)))
        self._channels[channel].users.add(client)
        self.users[client].channels.add(channel)

    def sjoin(self, server, channel, users, ts=None, modes=set()):
        """Sends an SJOIN for a group of users to a channel.

        The sender should always be a Server ID (SID). TS is optional, and defaults
        to the one we've stored in the channel state if not given.
        <users> is a list of (prefix mode, UID) pairs:

        Example uses:
            sjoin('100', '#test', [('', '100AAABBC'), ('qo', '100AAABBB'), ('h', '100AAADDD')])
            sjoin(self.sid, '#test', [('o', self.pseudoclient.uid)])
        """
        server = server or self.sid
        assert users, "sjoin: No users sent?"
        log.debug('(%s) sjoin: got %r for users', self.name, users)

        if not server:
            raise LookupError('No such PyLink client exists.')

        # Strip out list-modes, they shouldn't ever be sent in FJOIN (protocol rules).
        modes = modes or self._channels[channel].modes
        orig_ts = self._channels[channel].ts
        ts = ts or orig_ts

        banmodes = []
        regularmodes = []
        for mode in modes:
            modechar = mode[0][-1]
            if modechar in self.cmodes['*A']:
                # Track bans separately (they are sent as a normal FMODE instead of in FJOIN).
                # However, don't reset bans that have already been set.
                if (modechar, mode[1]) not in self._channels[channel].modes:
                    banmodes.append(mode)
            else:
                regularmodes.append(mode)

        uids = []
        changedmodes = set(modes)
        namelist = []

        # We take <users> as a list of (prefixmodes, uid) pairs.
        for userpair in users:
            assert len(userpair) == 2, "Incorrect format of userpair: %r" % userpair
            prefixes, user = userpair
            namelist.append(','.join(userpair))
            uids.append(user)
            for m in prefixes:
                changedmodes.add(('+%s' % m, user))
            try:
                self.users[user].channels.add(channel)
            except KeyError:  # Not initialized yet?
                log.debug("(%s) sjoin: KeyError trying to add %r to %r's channel list?", self.name, channel, user)

        namelist = ' '.join(namelist)
        self._send_with_prefix(server, "FJOIN {channel} {ts} {modes} :{users}".format(
                ts=ts, users=namelist, channel=channel,
                modes=self.join_modes(regularmodes)))
        self._channels[channel].users.update(uids)

        if banmodes:
            # Burst ban modes if there are any.
            # <- :1ML FMODE #test 1461201525 +bb *!*@bad.user *!*@rly.bad.user
            self._send_with_prefix(server, "FMODE {channel} {ts} {modes}".format(
                ts=ts, channel=channel, modes=self.join_modes(banmodes)))

        self.updateTS(server, channel, ts, changedmodes)

    def _oper_up(self, target, opertype=None):
        """Opers a client up (internal function specific to InspIRCd).

        This should be called whenever user mode +o is set on anyone, because
        InspIRCd requires a special command (OPERTYPE) to be sent in order to
        recognize ANY non-burst oper ups."""
        userobj = self.users[target]
        try:
            otype = opertype or userobj.opertype or 'IRC Operator'
        except AttributeError:
            log.debug('(%s) opertype field for %s (%s) isn\'t filled yet!',
                      self.name, target, userobj.nick)
            otype = 'IRC Operator'
        assert otype, "Tried to send an empty OPERTYPE!"
        log.debug('(%s) Sending OPERTYPE from %s to oper them up.',
                  self.name, target)
        userobj.opertype = otype

        # InspIRCd 2.x uses _ in OPERTYPE to denote spaces, while InspIRCd 3.x/4.x use trailing text.
        if self.negotiated_proto_ver < 1205:
            otype = otype.replace(" ", "_")
        else:
            otype = ':' + otype

        self._send_with_prefix(target, 'OPERTYPE %s' % otype)

    def mode(self, numeric, target, modes, ts=None):
        """Sends mode changes from a PyLink client/server."""
        if (not self.is_internal_client(numeric)) and \
                (not self.is_internal_server(numeric)):
            raise LookupError('No such PyLink client/server exists.')

        if ('+o', None) in modes and not self.is_channel(target):
            # Servers need OPERTYPE to set umode +o on people.
            self._oper_up(target)

        self.apply_modes(target, modes)
        joinedmodes = self.join_modes(modes)

        if self.is_channel(target):
            ts = ts or self._channels[target].ts
            self._send_with_prefix(numeric, 'FMODE %s %s %s' % (target, ts, joinedmodes))
        else:
            self._send_with_prefix(numeric, 'MODE %s %s' % (target, joinedmodes))

    def kill(self, numeric, target, reason):
        """Sends a kill from a PyLink client/server."""
        if (not self.is_internal_client(numeric)) and \
                (not self.is_internal_server(numeric)):
            raise LookupError('No such PyLink client/server exists.')

        if numeric in self.servers:
            sourcenick = self.servers[numeric].name
        else:
            sourcenick = self.users[numeric].nick

        self._send_with_prefix(numeric, 'KILL %s :Killed (%s (%s))' % (target, sourcenick, reason))
        self._remove_client(target)

    def topic(self, source, target, text):
        """Sends a topic change from a PyLink client."""
        if not self.is_internal_client(source):
            raise LookupError('No such PyLink client exists.')

        if self.negotiated_proto_ver >= 1205:
            self._send_with_prefix(source, 'FTOPIC %s %s %s :%s' %
                                   (target, self._channels[target].ts, int(time.time()), text))
        else:
            return super().topic(source, target, text)

    def topic_burst(self, source, target, text):
        """Sends a topic change from a PyLink server. This is usually used on burst."""
        if not self.is_internal_server(source):
            raise LookupError('No such PyLink server exists.')

        topic_ts = int(time.time())
        servername = self.servers[source].name

        if self.negotiated_proto_ver >= 1205:
            self._send_with_prefix(source, 'FTOPIC %s %s %s %s :%s' %
                                   (target, self._channels[target].ts, topic_ts, servername, text))
        else:
            self._send_with_prefix(source, 'FTOPIC %s %s %s :%s' % (target, topic_ts, servername, text))

        self._channels[target].topic = text
        self._channels[target].topicset = True

    def knock(self, numeric, target, text):
        """Sends a KNOCK from a PyLink client."""
        if not self.is_internal_client(numeric):
            raise LookupError('No such PyLink client exists.')
        self._send_with_prefix(numeric, 'ENCAP * KNOCK %s :%s' % (target, text))

    def update_client(self, target, field, text):
        """Updates the ident, host, or realname of any connected client."""
        field = field.upper()

        if field not in ('IDENT', 'HOST', 'REALNAME', 'GECOS'):
            raise NotImplementedError("Changing field %r of a client is "
                                      "unsupported by this protocol." % field)

        if self.is_internal_client(target):
            # It is one of our clients, use FIDENT/FHOST/FNAME.
            if field == 'IDENT':
                self.users[target].ident = text
                if self.negotiated_proto_ver >= 1206:
                    self._send_with_prefix(target, 'FIDENT %s *' % text)
                else:
                    self.users[target].realident = text
                    self._send_with_prefix(target, 'FIDENT %s' % text)
            elif field == 'HOST':
                self.users[target].host = text
                if self.negotiated_proto_ver >= 1206:
                    self._send_with_prefix(target, 'FHOST %s *' % text)
                else:
                    self._send_with_prefix(target, 'FHOST %s' % text)
            elif field in ('REALNAME', 'GECOS'):
                self.users[target].realname = text
                self._send_with_prefix(target, 'FNAME :%s' % text)
        else:
            # It is a client on another server, use CHGIDENT/CHGHOST/CHGNAME.
            if field == 'IDENT':
                if not self._has_module('chgident'):
                    raise NotImplementedError('Cannot change idents as chgident module is not loaded')

                self.users[target].ident = text
                self._send_with_prefix(self.sid, 'CHGIDENT %s %s' % (target, text))

                self.call_hooks([self.sid, 'CHGIDENT', {'target': target, 'newident': text}])
            elif field == 'HOST':
                if not self._has_module('chghost'):
                    raise NotImplementedError('Cannot change hosts as chghost module is not loaded')

                self.users[target].host = text
                self._send_with_prefix(self.sid, 'CHGHOST %s %s' % (target, text))

                self.call_hooks([self.sid, 'CHGHOST', {'target': target, 'newhost': text}])
            elif field in ('REALNAME', 'GECOS'):
                if not self._has_module('chgname'):
                    raise NotImplementedError('Cannot change real names as chgname module is not loaded')

                self.users[target].realname = text
                self._send_with_prefix(self.sid, 'CHGNAME %s :%s' % (target, text))

                self.call_hooks([self.sid, 'CHGNAME', {'target': target, 'newgecos': text}])

    def oper_notice(self, source, text):
        """Send a message to all opers."""
        self._send_with_prefix(self.sid, 'SNONOTICE G :From %s: %s' % (self.get_friendly_name(source), text))

    def numeric(self, source, numeric, target, text):
        """Sends raw numerics from a server to a remote client."""
        if self.negotiated_proto_ver >= 1205:
            # :<sid> NUM <numeric source sid> <target uuid> <numeric ID> <params>
            self._send_with_prefix(self.sid, 'NUM %s %s %s %s' % (source, target, numeric, text))
        else:
            self._send_with_prefix(self.sid, 'PUSH %s ::%s %s %s %s' % (target, source, numeric, target, text))

    def invite(self, source, target, channel):
        """Sends an INVITE from a PyLink client."""
        if not self.is_internal_client(source):
            raise LookupError('No such PyLink client exists.')

        if self.negotiated_proto_ver >= 1205:
            self._send_with_prefix(source, 'INVITE %s %s %d' % (target, channel, self._channels[channel].ts))
        else:
            self._send_with_prefix(source, 'INVITE %s %s' % (target, channel))

    def away(self, source, text):
        """Sends an AWAY message from a PyLink client. <text> can be an empty string
        to unset AWAY status."""
        if text:
            self._send_with_prefix(source, 'AWAY %s :%s' % (int(time.time()), text))
        else:
            self._send_with_prefix(source, 'AWAY')
        self.users[source].away = text

    def spawn_server(self, name, sid=None, uplink=None, desc=None):
        """
        Spawns a server off a PyLink server. desc (server description)
        defaults to the one in the config. uplink defaults to the main PyLink
        server, and sid (the server ID) is automatically generated if not
        given.
        """
        uplink = uplink or self.sid
        name = name.lower()
        desc = desc or self.serverdata.get('serverdesc') or conf.conf['pylink']['serverdesc']

        if sid is None:
            sid = self.sidgen.next_sid()

        assert len(sid) == 3, "Incorrect SID length"
        if sid in self.servers:
            raise ValueError('A server with SID %r already exists!' % sid)

        for server in self.servers.values():
            if name == server.name:
                raise ValueError('A server named %r already exists!' % name)

        if not self.is_internal_server(uplink):
            raise ValueError('Server %r is not a PyLink server!' % uplink)

        if not self.is_server_name(name):
            raise ValueError('Invalid server name %r' % name)

        self.servers[sid] = Server(self, uplink, name, internal=True, desc=desc)
        if self.negotiated_proto_ver >= 1205:
            # <- :3IN SERVER services.abc.local 0SV :Some server
            self._send_with_prefix(uplink, 'SERVER %s %s :%s' % (name, sid, desc))
        else:
            # <- :00A SERVER test.server * 1 00C :test
            self._send_with_prefix(uplink, 'SERVER %s * %s %s :%s' %
                                   (name, self.servers[sid].hopcount, sid, desc))

        def endburstf():
            if self._aborted.wait(self._endburst_delay):
                log.debug('(%s) stopping endburstf() for %s as aborted was set', self.name, sid)
                return
            self._send_with_prefix(sid, 'ENDBURST')

        if self._endburst_delay:
            t = threading.Thread(target=endburstf,
                                 name="protocols/inspircd delayed ENDBURST thread for %s@%s" % (sid, self.name))
            t.daemon = True
            t.start()
        else:
            self._send_with_prefix(sid, 'ENDBURST')
        return sid

    def set_server_ban(self, source, duration, user='*', host='*', reason='User banned'):
        """Sets a server ban."""
        assert not (user == host == '*'), "Refusing to set ridiculous ban on *@*"
        self._send_with_prefix(source, 'ADDLINE G %s@%s %s %s %s :%s' %
                               (user, host, self.get_friendly_name(source)[:64],
                                int(time.time()), duration, reason))

    ### Core / command handlers

    def _post_disconnect(self):
        super()._post_disconnect()
        log.debug('(%s) _post_disconnect: clearing _modsupport entries. Last: %s', self.name, self._modsupport)
        self._modsupport.clear()

    def post_connect(self):
        """Initializes CAPAB negotiation with the uplink server.

        We send CAPAB START here and complete CAPAB CAPABILITIES / CAPAB END /
        SERVER / BURST once we receive CAPAB END from the uplink, so that we
        mirror the uplink's CASEMAPPING and negotiated protocol version cleanly
        (required by InspIRCd 4 / protocol 1206).
        """
        self._handshake_sent = False
        self.send('CAPAB START %s' % self.proto_ver)

    def _send_handshake(self):
        """Completes CAPAB negotiation, SERVER authentication, and initial BURST."""
        if self._handshake_sent:
            return
        self._handshake_sent = True

        ver = self.negotiated_proto_ver
        ts = self.start_ts
        f = self.send

        if ver >= 1205:
            f('CAPAB CAPABILITIES :PROTOCOL=%s CASEMAPPING=%s' % (ver, self.casemapping))
        else:
            f('CAPAB CAPABILITIES :PROTOCOL=%s' % ver)
        f('CAPAB END')

        host = self.serverdata["hostname"]
        sdesc = self.serverdata.get('serverdesc') or conf.conf['pylink']['serverdesc']
        if ver >= 1205:
            server_line = 'SERVER {host} {Pass} {sid} :{sdesc}'
        else:
            server_line = 'SERVER {host} {Pass} 0 {sid} :{sdesc}'
        f(server_line.format(host=host, Pass=self.serverdata["sendpass"], sid=self.sid, sdesc=sdesc))

        self._send_with_prefix(self.sid, 'BURST %s' % ts)

        verstr = self.version()
        shortver = verstr.split(' ', 1)[0]
        if ver >= 1206:
            self._send_with_prefix(self.sid, 'SINFO rawversion :%s' % shortver)
            self._send_with_prefix(self.sid, 'SINFO customversion :%s' % verstr)
        elif ver >= 1205:
            for version_type in ('version', 'rawversion'):
                self._send_with_prefix(self.sid, 'SINFO %s :%s' % (version_type, shortver))
            self._send_with_prefix(self.sid, 'SINFO fullversion :%s' % verstr)
        else:
            self._send_with_prefix(self.sid, 'VERSION :%s' % verstr)

        self._send_with_prefix(self.sid, 'ENDBURST')

    def handle_capab(self, source, command, args):
        """
        Handles the CAPAB command, used for capability negotiation with our uplink.
        """
        if not args:
            return

        subcmd = args[0].upper()

        if subcmd == 'START':
            # <- CAPAB START 1202 / 1205 / 1206
            self.remote_proto_ver = protocol_version = int(args[1])

            log.debug("(%s) handle_capab: got remote protocol version %s (local target=%s, negotiated=%s)",
                      self.name, protocol_version, self.proto_ver, self.negotiated_proto_ver)
            if protocol_version < self.proto_ver:
                raise ProtocolError("Remote protocol version is too old! "
                                    "At least %s is needed. (got %s)" %
                                    (self.proto_ver, protocol_version))
            elif protocol_version > self.MAX_PROTO_VER:
                log.warning("(%s) PyLink support for InspIRCd > 4.x is experimental, "
                            "and should not be relied upon for anything important.",
                            self.name)
            elif protocol_version >= 1206 > self.proto_ver:
                log.warning("(%s) PyLink introduces native support for InspIRCd 4. "
                            "Enable this by setting 'target_version' to 'insp4' in your InspIRCd "
                            "server block. Otherwise, some features will not work correctly!",
                            self.name)
                log.warning("(%s) Falling back to InspIRCd 3 compatibility mode.", self.name)
            elif protocol_version >= 1205 > self.proto_ver:
                log.warning("(%s) PyLink 3.0 introduces native support for InspIRCd 3. "
                            "You should enable this by setting the 'target_version' option in your "
                            "InspIRCd server block to 'insp3'. Otherwise, some features will not "
                            "work correctly!", self.name)
                log.warning("(%s) Falling back to InspIRCd 2.0 (compatibility) mode.", self.name)

            if self.negotiated_proto_ver >= 1205:
                # Clear mode lists; they will be negotiated during CAPAB
                self.cmodes = {'*A': '', '*B': '', '*C': '', '*D': ''}
                self.umodes = {'*A': '', '*B': '', '*C': '', '*D': ''}
                self.prefixmodes.clear()

        elif subcmd in {'CHANMODES', 'USERMODES'}:
            mydict = self.cmodes if subcmd == 'CHANMODES' else self.umodes

            for modepair in args[-1].split():
                if '=' not in modepair:
                    continue
                name, char = modepair.rsplit('=', 1)
                if not char:
                    continue

                if self.negotiated_proto_ver >= 1205:
                    parts = name.split(':')
                    modetype = parts[0]
                    name = parts[-1]

                    if modetype == 'simple':       # No parameter
                        mydict['*D'] += char[-1]
                    elif modetype == 'param-set':  # Only parameter when setting (e.g. +l)
                        mydict['*C'] += char[-1]
                    elif modetype == 'param':      # Always has parameter (e.g. +k)
                        mydict['*B'] += char[-1]
                    elif modetype == 'list':       # List modes like ban, except, invex...
                        mydict['*A'] += char[-1]
                    elif modetype == 'prefix':     # prefix:30000:op=@o
                        if subcmd != 'CHANMODES':
                            log.warning("(%s) Possible desync? Got a prefix type modepair %r but not for channel modes",
                                        self.name, modepair)
                        else:
                            if len(parts) >= 2 and parts[1].isdigit():
                                self._prefix_levels[name] = int(parts[1])
                            if len(char) >= 2:
                                self.prefixmodes[char[-1]] = char[0]

                # Strip c_, u_ prefixes to be consistent with other protocols.
                if name.startswith(('c_', 'u_')):
                    name = name[2:]

                if name == 'reginvite':
                    name = 'regonly'
                elif name == 'antiredirect':
                    name = 'noforward'
                elif name == 'founder':
                    name = 'owner'
                elif name in ('repeat', 'kicknorejoin'):
                    name += '_insp'

                mydict[name] = char[-1]

        elif subcmd == 'EXTBANS':
            # InspIRCd 4 (1206):
            # <- CAPAB EXTBANS :acting:mute=m matching:account=R matching:channel=j ...
            for extban in args[-1].split():
                if ':' not in extban:
                    continue
                exttype, rest = extban.split(':', 1)
                if '=' in rest:
                    extname, extchar = rest.split('=', 1)
                    prefix = (extchar or extname) + ':'
                else:
                    extname = rest
                    prefix = extname + ':'

                extname_l = extname.lower()
                if exttype == 'acting':
                    mapped = INSP4_ACTING_EXTBAN_MAP.get(extname_l)
                    if mapped:
                        self.extbans_acting[mapped] = prefix
                elif exttype == 'matching':
                    mapped = INSP4_MATCHING_EXTBAN_MAP.get(extname_l)
                    if mapped:
                        self.extbans_matching[mapped] = prefix

            log.debug('(%s) handle_capab: updated extbans_acting=%r extbans_matching=%r',
                      self.name, self.extbans_acting, self.extbans_matching)

        elif subcmd == 'CAPABILITIES':
            caps = self.parse_isupport(args[-1])
            log.debug("(%s) handle_capab: capabilities list is %s", self.name, caps)

            nickmax = caps.get('MAXNICK') or caps.get('NICKMAX')
            if nickmax:
                self.maxnicklen = int(nickmax)

            # Note: in InspIRCd 4, MAXCHANNEL is the max channels a user can join,
            # while MAXCHAN (v4) / CHANMAX (v2/v3) is max channel name length.
            chanmax = caps.get('MAXCHAN') or caps.get('CHANMAX')
            if chanmax:
                self.maxchanlen = int(chanmax)

            if 'CASEMAPPING' in caps:
                self.casemapping = caps['CASEMAPPING']
                log.debug('(%s) handle_capab: updated casemapping to %s', self.name, self.casemapping)

            # InspIRCd 2 only: mode & prefix definitions are sent in CAPAB CAPABILITIES
            if self.negotiated_proto_ver < 1205:
                if 'CHANMODES' in caps:
                    self.cmodes['*A'], self.cmodes['*B'], self.cmodes['*C'], self.cmodes['*D'] \
                        = caps['CHANMODES'].split(',')
                if 'USERMODES' in caps:
                    self.umodes['*A'], self.umodes['*B'], self.umodes['*C'], self.umodes['*D'] \
                        = caps['USERMODES'].split(',')
                if 'PREFIX' in caps:
                    self.prefixmodes = self.parse_isupport_prefixes(caps['PREFIX'])
                    log.debug('(%s) handle_capab: self.prefixmodes set to %r', self.name,
                              self.prefixmodes)

        elif subcmd in {'MODULES', 'MODSUPPORT'}:
            for module in args[-1].split():
                self._add_module_support(module)

        elif subcmd == 'END':
            self._send_handshake()

    def handle_kick(self, source, command, args):
        """Handles incoming KICKs."""
        # InspIRCd 3/4 adds membership IDs to KICK messages when forwarding across servers
        if self.negotiated_proto_ver >= 1205 and len(args) > 3:
            del args[2]

        return super().handle_kick(source, command, args)

    def handle_ping(self, source, command, args):
        """Handles incoming PING commands, so we don't time out."""
        # InspIRCd 2: <- :70M PING 70M 0AL -> :0AL PONG 0AL 70M
        # InspIRCd 3/4: <- :3IN PING 808 -> :808 PONG 3IN
        if len(args) >= 2:
            self._send_with_prefix(args[1], 'PONG %s %s' % (args[1], source), queue=False)
        else:
            self._send_with_prefix(args[0], 'PONG %s' % source, queue=False)

    def handle_fjoin(self, servernumeric, command, args):
        """Handles incoming FJOIN commands (InspIRCd equivalent of JOIN/SJOIN)."""
        # insp2: <- :70M FJOIN #chat 1423790411 +AFPfjnt 6:5 7:5 9:5 :o,1SRAABIT4 v,1IOAAF53R
        # insp3/4: <- :3IN FJOIN #test 1556842195 +nt :o,3INAAAAAA:4
        channel = args[0]
        chandata = self._channels[channel].deepcopy()
        userlist = args[-1].split() if args[-1] else []

        modestring = args[2:-1] or [args[2]]
        parsedmodes = self.parse_modes(channel, modestring)
        namelist = []
        changedmodes = set(parsedmodes)

        for entry in userlist:
            if ',' not in entry:
                continue
            modeprefix, user = entry.split(',', 1)

            if self.negotiated_proto_ver >= 1205:
                # Strip membership ID (<uid>:<membid>)
                user = user.split(':', 1)[0]

            if user not in self.users:
                log.debug('(%s) handle_fjoin: tried to introduce user %s not in our user list, ignoring...',
                          self.name, user)
                continue

            namelist.append(user)
            self.users[user].channels.add(channel)
            changedmodes |= {('+%s' % mode, user) for mode in modeprefix}
            self._channels[channel].users.add(user)

        their_ts = int(''.join(char for char in args[1] if char.isdigit()))
        self.updateTS(servernumeric, channel, their_ts, changedmodes)

        return {'channel': channel, 'users': namelist, 'modes': parsedmodes, 'ts': their_ts,
                'channeldata': chandata}

    def handle_ijoin(self, source, command, args):
        """Handles InspIRCd 3/4 joins with membership ID."""
        # <- :<uid> IJOIN <chan> <membid> [<ts> [<flags>]]
        channel = args[0]
        self.users[source].channels.add(channel)
        self._channels[channel].users.add(source)

        if len(args) >= 3:
            their_ts = int(''.join(char for char in args[2] if char.isdigit()))
            changedmodes = {('+%s' % mode, source) for mode in args[3]} if len(args) >= 4 else set()
            self.updateTS(source, channel, their_ts, changedmodes)

        return {'channel': channel, 'users': [source], 'modes': self._channels[channel].modes}

    def handle_lmode(self, numeric, command, args):
        """Handles InspIRCd 4 LMODE commands (bursting channel list modes like +b/+e/+I)."""
        # <- :36D LMODE #chan 1234567890 b *!*@bad.host 1234567891 setter *!*@other.host 1234567892 setter
        if len(args) < 3:
            log.debug('(%s) handle_lmode: ignoring malformed LMODE %r', self.name, args)
            return

        channel = args[0]
        their_ts = int(''.join(char for char in args[1] if char.isdigit()))
        modechar = args[2]
        oldobj = self._channels[channel].deepcopy()

        changedmodes = []
        entries = args[3:]
        for i in range(0, len(entries), 3):
            changedmodes.append(('+%s' % modechar, entries[i]))

        if changedmodes:
            self.updateTS(numeric, channel, their_ts, changedmodes)

        return {'target': channel, 'modes': changedmodes, 'ts': their_ts,
                'channeldata': oldobj}

    def handle_uid(self, numeric, command, args):
        """Handles incoming UID commands (user introduction)."""
        uid = args[0]
        ts = int(args[1])
        nick = args[2]
        realhost = args[3]
        host = args[4]

        if self.negotiated_proto_ver >= 1206:
            # InspIRCd 4 (1206):
            # :<sid> UID <uid> <age> <nick> <realhost> <dhost> <realuser> <duser> <ip> <signon> <modes> [<params>...] :<realname>
            realident = args[5]
            ident = args[6]
            ip = args[7]
            signon_idx = 8
        else:
            # InspIRCd 2/3 (1202/1205):
            # :<sid> UID <uid> <age> <nick> <realhost> <dhost> <duser> <ip> <signon> <modes> [<params>...] :<realname>
            ident = args[5]
            realident = ident
            ip = args[6]
            signon_idx = 7

        self._check_nick_collision(nick)
        realname = args[-1]
        self.users[uid] = userobj = User(self, nick, ts, uid, numeric, ident, host, realname, realhost, ip)
        userobj.realident = realident

        mode_tokens = args[signon_idx + 1:-1] or ['+']
        parsedmodes = self.parse_modes(uid, mode_tokens)
        self.apply_modes(uid, parsedmodes)

        self._check_oper_status_change(uid, parsedmodes)

        self.servers[numeric].users.add(uid)
        # InspIRCd sends SSL status in METADATA, so it is not known yet at UID time
        return {'uid': uid, 'ts': ts, 'nick': nick, 'realhost': realhost, 'host': host,
                'ident': ident, 'ip': ip, 'secure': None}

    def handle_server(self, source, command, args):
        """Handles incoming SERVER commands (introduction of servers)."""
        if self.uplink is None:
            # Direct uplink introduction:
            # insp20: SERVER <name> <pass> <hops> <sid> :<desc>
            # insp3:  SERVER <name> <pass> [0] <sid> [k=v...] :<desc>
            # insp4:  SERVER <name> <pass> <sid> [k=v...] :<desc>
            servername = args[0].lower()
            if len(args) < 4:
                raise ProtocolError('Malformed SERVER introduction from uplink: %r' % (args,))

            if args[1] != self.serverdata['recvpass']:
                raise ProtocolError('recvpass from uplink server %s does not match configuration!' % servername)

            if self.negotiated_proto_ver >= 1206:
                source = args[2]
            elif self.negotiated_proto_ver >= 1205:
                # Some InspIRCd 3.x builds include the legacy hopcount '0' before SID
                if len(args) >= 5 and args[2].isdigit() and len(args[2]) < 3:
                    source = args[3]
                else:
                    source = args[2]
            else:
                if len(args) < 5:
                    raise ProtocolError('Malformed SERVER introduction from uplink (missing SID)')
                source = args[3]

            sdesc = args[-1]
            self.servers[source] = Server(self, None, servername, desc=sdesc)
            self.uplink = source
            log.debug('(%s) inspircd: found uplink %s', self.name, self.uplink)
            return

        # Indirect server introductions:
        # insp20: :<uplink> SERVER <name> * <hops> <sid> :<desc>
        # insp3/4: :<uplink> SERVER <name> <sid> [hidden=0 burst=...] :<desc>
        servername = args[0].lower()
        if self.negotiated_proto_ver >= 1205:
            sid = args[1]
        else:
            sid = args[3]
        sdesc = args[-1]
        self.servers[sid] = Server(self, source, servername, desc=sdesc)

        return {'name': servername, 'sid': sid, 'text': sdesc}

    def handle_fmode(self, numeric, command, args):
        """Handles the FMODE command, used for channel mode changes."""
        channel = args[0]
        oldobj = self._channels[channel].deepcopy()
        modes = args[2:]
        changedmodes = self.parse_modes(channel, modes)
        self.apply_modes(channel, changedmodes)
        ts = int(args[1])
        return {'target': channel, 'modes': changedmodes, 'ts': ts,
                'channeldata': oldobj}

    def handle_idle(self, source, command, args):
        """Handles the IDLE command, sent between servers in remote WHOIS queries."""
        if self.serverdata.get('force_whois_extensions', True):
            return {'target': args[0], 'parse_as': 'WHOIS'}

        target = args[0]
        start_time = self.start_ts if (conf.conf['pylink'].get('whois_show_startup_time', True) and
                                       self.get_service_bot(target)) else 0
        self._send_with_prefix(target, 'IDLE %s %s 0' % (source, start_time))

    def handle_ftopic(self, source, command, args):
        """Handles incoming topic changes."""
        channel = args[0]

        if self.negotiated_proto_ver >= 1205 and command == 'FTOPIC':
            ts = args[2]
            if source in self.users:
                setter = source
            else:
                setter = args[3]
        else:
            ts = args[1]
            setter = args[2]
        ts = int(ts)

        topic = args[-1]
        self._channels[channel].topic = topic
        self._channels[channel].topicset = True
        return {'channel': channel, 'setter': setter, 'ts': ts, 'text': topic}

    # SVSTOPIC is used by InspIRCd module topiclock - its arguments are the same as insp2 FTOPIC
    handle_svstopic = handle_ftopic

    def handle_opertype(self, target, command, args):
        """Handles incoming OPERTYPE, which is used to denote an oper up."""
        opertype = args[0]
        if self.negotiated_proto_ver < 1205:
            opertype = opertype.replace("_", " ")

        omode = [('+o', None)]
        self.apply_modes(target, omode)

        self.call_hooks([target, 'CLIENT_OPERED', {'text': opertype}])
        return {'target': target, 'modes': omode}

    def handle_fident(self, numeric, command, args):
        """Handles FIDENT, used for denoting ident changes."""
        display_ident = args[0]
        real_ident = args[1] if len(args) > 1 else None

        if display_ident != '*':
            self.users[numeric].ident = display_ident
        if real_ident and real_ident != '*':
            self.users[numeric].realident = real_ident

        return {'target': numeric, 'newident': self.users[numeric].ident}

    def handle_fhost(self, numeric, command, args):
        """Handles FHOST, used for denoting hostname changes."""
        display_host = args[0]
        real_host = args[1] if len(args) > 1 else None

        if display_host != '*':
            self.users[numeric].host = display_host
        if real_host and real_host != '*':
            self.users[numeric].realhost = real_host

        return {'target': numeric, 'newhost': self.users[numeric].host}

    def handle_fname(self, numeric, command, args):
        """Handles FNAME, used for denoting real name/gecos changes."""
        self.users[numeric].realname = newgecos = args[0]
        return {'target': numeric, 'newgecos': newgecos}

    def handle_endburst(self, numeric, command, args):
        """ENDBURST handler; sends a hook with empty contents."""
        self.servers[numeric].has_eob = True
        if numeric == self.uplink:
            self.connected.set()
        return {}

    def handle_away(self, numeric, command, args):
        """Handles incoming AWAY messages."""
        try:
            ts = args[0]
            self.users[numeric].away = text = args[1]
            return {'text': text, 'ts': ts}
        except IndexError:
            self.users[numeric].away = ''
            return {'text': ''}

    def handle_rsquit(self, numeric, command, args):
        """Handles the RSQUIT command, sent by opers to SQUIT remote servers."""
        target = self._get_SID(args[0])
        if self.is_internal_server(target):
            uplink = self.servers[target].uplink
            reason = 'Requested by %s' % self.get_hostmask(numeric)
            self._send_with_prefix(uplink, 'SQUIT %s :%s' % (target, reason))
            return self.handle_squit(numeric, 'SQUIT', [target, reason])
        else:
            log.debug("(%s) Got RSQUIT for '%s', which is either invalid or not "
                      "a server of ours!", self.name, args[0])

    def handle_metadata(self, numeric, command, args):
        """
        Handles the METADATA command across InspIRCd 2/3/4:
        - Network/Server: METADATA * <key> [:<value>]
        - User:           METADATA <uid> <key> [:<value>]
        - Channel:        METADATA <#chan> <ts> <key> [:<value>]
        - Membership v4:  METADATA @ <uid> <#chan> <ts> <membid> <key> [:<value>]
        """
        if len(args) < 2:
            return

        target = args[0]

        # InspIRCd 4 membership metadata - currently unused by PyLink
        if target == '@':
            return

        # Channel metadata (METADATA #chan <ts> <key> [:<value>])
        if self.is_channel(target):
            return

        key = args[1]
        value = args[2] if len(args) >= 3 else ''

        if target == '*':
            if key == 'modules' and numeric == self.uplink:
                for module in value.split():
                    if module.startswith('-'):
                        log.debug('(%s) Removing module %s', self.name, module[1:])
                        self._remove_module_support(module[1:])
                    elif module.startswith('+'):
                        log.debug('(%s) Adding module %s', self.name, module[1:])
                        self._add_module_support(module[1:])
                    else:
                        log.warning('(%s) Got unknown METADATA modules string: %r', self.name, value)
        elif target in self.users:
            if key == 'accountname':
                self.call_hooks([target, 'CLIENT_SERVICES_LOGIN', {'text': value}])
            elif key in ('ssl_cert', 'tls_cert'):
                self.users[target].ssl = bool(value)

    def handle_version(self, numeric, command, args):
        """Stub VERSION handler to override the one in ts6_common."""

    def handle_burst(self, numeric, command, args):
        """Stub BURST handler."""

    def handle_sinfo(self, numeric, command, args):
        """Stub SINFO handler."""

    def handle_tagmsg(self, numeric, command, args):
        """Stub TAGMSG handler (IRCv3 client tags forwarded over InspIRCd 4 S2S)."""

    def handle_resync(self, numeric, command, args):
        """Stub RESYNC handler (InspIRCd 4 channel resync request)."""

    def handle_sakick(self, source, command, args):
        """Handles forced kicks (SAKICK)."""
        target = args[1]
        channel = args[0]
        try:
            reason = args[2]
        except IndexError:
            reason = self.get_friendly_name(source)

        if not self.is_internal_client(target):
            log.warning("(%s) Got SAKICK for client that not one of ours: %s", self.name, target)
            return
        else:
            server = self.get_server(target)

        self.kick(server, channel, target, reason)
        return {'channel': channel, 'target': target, 'text': reason}

    def handle_alltime(self, source, command, args):
        """Handles /ALLTIME requests."""
        timestring = '%s (%s)' % (time.strftime('%Y-%m-%d %H:%M:%S'), int(time.time()))
        self._send_with_prefix(self.sid, 'NOTICE %s :System time is %s on %s' %
                               (source, timestring, self.hostname()))


Class = InspIRCdProtocol
