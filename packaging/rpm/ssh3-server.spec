# ssh3 rpm spec - the ssh3-server daemon and the ssh3 client, packaged by
# packaging/build.sh, which copies this template into the rpmbuild tree with
# @VERSION@ substituted from the binary (-V output). the payload is the
# prebuilt binaries: %prep/%build are intentionally empty, rpmbuild only
# wraps them.
#
# the split mirrors the debian source package (packaging/debian/control)
# and the openssh canon: ssh3-server is the daemon, ssh3-client the CLI.
# the two halves are independent packages - the rpm channel keeps the
# system-openssl scheme, so the client of a serverless host needs no daemon
# and the daemon needs no client.
#
# target: fedora/rhel-style systems with openssl-libs >= 3.5 (the QUIC TLS
# API). older fedoras carry 3.0.x/3.2.x and cannot run this pair.

Name:           ssh3-server
Version:        @VERSION@
Release:        1%{?dist}
Summary:        SSH3 server - SSH over QUIC/HTTP3 transport
License:        BSD-2-Clause
BuildArch:      @RPMARCH@

Source0:        ssh3-server
Source1:        LICENSE
Source2:        THIRD-PARTY-NOTICES.md
Source3:        README.md
Source4:        ssh3
Source5:        ssh3.1.gz

Requires:       openssl-libs >= 3.5
Conflicts:      ssh3-go-client
Conflicts:      ssh3-go-server
# the rpm spelling of the deb Replaces: the files move under these names
Obsoletes:      ssh3-go-client
Obsoletes:      ssh3-go-server

%description
SSH3 server daemon: the SSH3 protocol carried over HTTP/3 (QUIC),
implemented in C in the nginx style on top of the OpenSSL QUIC TLS API
(OpenSSL >= 3.5). Configured through environment variables and
command-line flags; drops privileges to the system user "ssh3" with
state under /var/lib/ssh3.

%package -n ssh3-client
Summary:        SSH3 client - SSH over QUIC/HTTP3 transport
Requires:       openssl-libs >= 3.5
Conflicts:      ssh3-go-client
# the rpm spelling of the deb Replaces: the binary moves under this name
Obsoletes:      ssh3-go-client

%description -n ssh3-client
The SSH3 client: sessions, the ssh(1)-canon forwards (-L/-R/-D with the
udp:// extension), -J proxy jumps, the control master (-M/-S/-O), the
agent forwarding (-A), file transfers (put|get, -r recursive) and the
in-process sftp subsystem, all over one HTTP/3 (QUIC) extended CONNECT
per target.
.
The CLI follows the ssh(1) canon: -4/-6, -e escape, -F ssh_config, -o
keyword overrides, -t/-T pty control, -V.  The first connection pins the
server certificate TOFU-style in ~/.ssh3/known_hosts.  See ssh3(1).

%prep
# an empty scratch build directory, the sources are copied in manually
%setup -c -T
cp %{SOURCE1} %{SOURCE2} %{SOURCE3} .
# the client package carries its own copy of the license: a spec cannot
# list the same file in two packages (rpmbuild: "File listed twice")
cp %{SOURCE1} LICENSE-CLIENT

%build
# nothing to build: the payload is the prebuilt binaries

%install
mkdir -p %{buildroot}%{_sbindir}
install -m 0755 %{SOURCE0} %{buildroot}%{_sbindir}/ssh3-server
mkdir -p %{buildroot}%{_bindir}
install -m 0755 %{SOURCE4} %{buildroot}%{_bindir}/ssh3
mkdir -p %{buildroot}%{_mandir}/man1
install -m 0644 %{SOURCE5} %{buildroot}%{_mandir}/man1/ssh3.1.gz

%files
%license LICENSE THIRD-PARTY-NOTICES.md
%doc README.md
%attr(0755,root,root) %{_sbindir}/ssh3-server

%files -n ssh3-client
%license LICENSE-CLIENT
%attr(0755,root,root) %{_bindir}/ssh3
%{_mandir}/man1/ssh3.1.gz

%changelog
* Mon Oct 05 2026 ssh3-c maintainers <maintainers@example.com> - @VERSION@-1
- initial packaging of ssh3-server and ssh3-client
