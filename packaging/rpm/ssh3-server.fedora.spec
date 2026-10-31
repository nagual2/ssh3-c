# ssh3 rpm spec - the Fedora review variant (the P8(2) plan item).
#
# the difference from packaging/rpm/ssh3-server.spec (the self-hosted
# channel, the prebuilt payload): the Fedora review builds from the
# source tarball (%build with the %cmake macro, %check rides ctest) -
# the prebuilt-binary packages do not pass the Fedora review. the
# Conflicts/Obsoletes against ssh3-go-* are dropped for the same
# reason: those packages do not exist in Fedora, and the review
# guidance flags conflicts against not-provided names.
#
# the OpenSSL floor: fedora 43 carries openssl 3.5.x (the QUIC TLS
# API), so BuildRequires openssl-devel >= 3.5 resolves against the
# system library - no subpackage, no bundle. older fedoras refuse at
# the %build stage (the cmake configure is the gate).

Name:           ssh3-server
Version:        0.5.6
Release:        1%{?dist}
Summary:        SSH3 server - SSH over QUIC/HTTP3 transport
License:        BSD-2-Clause
URL:            https://github.com/nagual2/ssh3-c
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  cmake
BuildRequires:  ninja-build
BuildRequires:  openssl-devel >= 3.5
BuildRequires:  zlib-devel
BuildRequires:  libzstd-devel
BuildRequires:  lz4-devel

Requires:       openssl-libs >= 3.5

%global _description %{expand:
SSH3 server daemon: the SSH3 protocol carried over HTTP/3 (QUIC),
implemented in C in the nginx style on top of the OpenSSL QUIC TLS API
(OpenSSL >= 3.5). Configured through environment variables and
command-line flags; drops privileges to the system user "ssh3" with
state under /var/lib/ssh3.}

%description %{_description}

%package -n ssh3-client
Summary:        SSH3 client - SSH over QUIC/HTTP3 transport
Requires:       openssl-libs >= 3.5

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
%autosetup -n ssh3-c-%{version}

%build
%cmake -DCMAKE_BUILD_TYPE=Release -G Ninja
%cmake_build --target ssh3-server ssh3

%install
install -Dm0755 %{_vpath_builddir}/ssh3-server %{buildroot}%{_sbindir}/ssh3-server
install -Dm0755 %{_vpath_builddir}/ssh3 %{buildroot}%{_bindir}/ssh3
install -Dm0644 packaging/debian/ssh3.1 %{buildroot}%{_mandir}/man1/ssh3.1
gzip %{buildroot}%{_mandir}/man1/ssh3.1

%check
%ctest

%files
%license LICENSE THIRD-PARTY-NOTICES.md
%doc README.md
%attr(0755,root,root) %{_sbindir}/ssh3-server

%files -n ssh3-client
%license LICENSE
%attr(0755,root,root) %{_bindir}/ssh3
%{_mandir}/man1/ssh3.1.gz

%changelog
* Thu Oct 30 2026 ssh3-c maintainers <maintainers@example.com> - 0.5.5-1
- the review variant: the source build, the go-fork conflicts dropped
