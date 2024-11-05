# DevSecOps-2024-v2
Задание по DevSecOps на сканирование контейнеров


Для выполнения задания был использован nginx:latest.

---

Была составлена таблица результатов:


| Vulnerability ID | Title |
|------------------|-------|
| CVE-2011-3374    | It was found that apt-key in apt, all versions, do not correctly valid ... |
| TEMP-0841856-B18BAF | [Privilege escalation possible to other user than root] |
| CVE-2022-0563    | util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline |
| CVE-2016-2781    | coreutils: Non-privileged session can escape to the parent session in chroot |
| CVE-2017-18018   | coreutils: race condition vulnerability in chown and chgrp |
| CVE-2024-8096    | curl: OCSP stapling bypass with GnuTLS |
| CVE-2024-2379    | curl: QUIC certificate check bypass with wolfSSL |
| CVE-2022-27943   | binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const |
| CVE-2023-4039    | gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 |
| CVE-2022-3219    | gnupg: denial of service issue (resource consumption) using compressed packets |
| CVE-2023-6879    | aom: heap-buffer-overflow on frame size change |
| CVE-2023-39616   | AOMedia v3.0.0 to v3.5.0 was discovered to contain an invalid read mem ... |
| CVE-2011-3374    | It was found that apt-key in apt, all versions, do not correctly valid ... |
| CVE-2022-0563    | util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline |
| CVE-2010-4756    | glibc: glob implementation can cause excessive CPU and memory consumption due to crafted glob expressions |
| CVE-2018-20796   | glibc: uncontrolled recursion in function check_dst_limits_calc_pos_1 in posix/regexec.c |
| CVE-2019-1010022 | glibc: stack guard protection bypass |
| CVE-2019-1010023 | glibc: running ldd on malicious ELF leads to code execution because of wrong size computation |
| CVE-2019-1010024 | glibc: ASLR bypass using cache of thread stack and heap |
| CVE-2019-1010025 | glibc: information disclosure of heap addresses of pthread_created thread |
| CVE-2019-9192    | glibc: uncontrolled recursion in function check_dst_limits_calc_pos_1 in posix/regexec.c |
| CVE-2010-4756    | glibc: glob implementation can cause excessive CPU and memory consumption due to crafted glob expressions |
| CVE-2018-20796   | glibc: uncontrolled recursion in function check_dst_limits_calc_pos_1 in posix/regexec.c |
| CVE-2019-1010022 | glibc: stack guard protection bypass |
| CVE-2019-1010023 | glibc: running ldd on malicious ELF leads to code execution because of wrong size computation |
| CVE-2019-1010024 | glibc: ASLR bypass using cache of thread stack and heap |
| CVE-2019-1010025 | glibc: information disclosure of heap addresses of pthread_created thread |
| CVE-2019-9192    | glibc: uncontrolled recursion in function check_dst_limits_calc_pos_1 in posix/regexec.c |
| CVE-2024-8096    | curl: OCSP stapling bypass with GnuTLS |
| CVE-2024-2379    | curl: QUIC certificate check bypass with wolfSSL |
| CVE-2023-32570   | VideoLAN dav1d before 1.2.0 has a thread_task.c race condition that ca ... |
| CVE-2023-51792   | Buffer Overflow vulnerability in libde265 v1.0.12 allows a local attac ... |
| CVE-2024-38949   | Heap Buffer Overflow vulnerability in Libde265 v1.0.15 allows attacker ... |
| CVE-2024-38950   | Heap Buffer Overflow vulnerability in Libde265 v1.0.15 allows attacker ... |
| CVE-2023-52425   | expat: parsing large tokens can trigger a denial of service |
| CVE-2024-50602   | libexpat: expat: DoS via XML_ResumeParser |
| CVE-2023-52426   | expat: recursive XML entity expansion vulnerability |
| CVE-2024-28757   | expat: XML Entity Expansion |
| CVE-2022-27943   | binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const |
| CVE-2023-4039    | gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 |
| CVE-2024-2236    | libgcrypt: vulnerable to Marvin Attack |
| CVE-2018-6829    | libgcrypt: ElGamal implementation doesn't have semantic security due to incorrectly encoded plaintexts possibly allowing to obtain sensitive information |
| CVE-2011-3389    | HTTPS: block-wise chosen-plaintext attack against SSL/TLS (BEAST) |
| CVE-2024-26462   | krb5: Memory leak at /krb5/src/kdc/ndr.c |
| CVE-2018-5709    | krb5: integer overflow in dbentry->n_key_data in kadmin/dbutil/dump.c |
| CVE-2024-26458   | krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c |
| CVE-2024-26461   | krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c |
| CVE-2023-49462   | libheif v1.17.5 was discovered to contain a segmentation violation via ... |
| CVE-2023-29659   | A Segmentation fault caused by a floating point exception exists in li ... |
| CVE-2024-41311   | In Libheif 1.17.6, insufficient checks in ImageOverlay::parse() decodi ... |
| CVE-2023-49463   | libheif v1.17.5 was discovered to contain a segmentation violation via ... |
| CVE-2024-25269   | libheif <= 1.17.6 contains a memory leak in the function JpegEncoder:: ... |
| CVE-2017-9937    | libtiff: memory malloc failure in tif_jbig.c could cause DOS. |
| CVE-2024-26462   | krb5: Memory leak at /krb5/src/kdc/ndr.c |
| CVE-2018-5709    | krb5: integer overflow in dbentry->n_key_data in kadmin/dbutil/dump.c |
| CVE-2024-26458   | krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c |
| CVE-2024-26461   | krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c |
| CVE-2024-26462   | krb5: Memory leak at /krb5/src/kdc/ndr.c |
| CVE-2018-5709    | krb5: integer overflow in dbentry->n_key_data in kadmin/dbutil/dump.c |
| CVE-2024-26458   | krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c |
| CVE-2024-26461   | krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c |
| CVE-2024-26462   | krb5: Memory leak at /krb5/src/kdc/ndr.c |
| CVE-2018-5709    | krb5: integer overflow in dbentry->n_key_data in kadmin/dbutil/dump.c |
| CVE-2024-26458   | krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c |
| CVE-2024-26461   | krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c |
| CVE-2023-2953    | openldap: null pointer dereference in  ber_memalloc_x  function |
| CVE-2015-3276    | openldap: incorrect multi-keyword mode cipherstring parsing |
| CVE-2017-14159   | openldap: Privilege escalation via PID file manipulation |
| CVE-2017-17740   | openldap: contrib/slapd-modules/nops/nops.c attempts to free stack buffer allowing remote attackers to cause a denial of service |
| CVE-2020-15719   | openldap: Certificate validation incorrectly matches name against CN-ID |
| CVE-2022-0563    | util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline |
| CVE-2024-28182   | nghttp2: CONTINUATION frames DoS |
| CVE-2024-10041   | pam: libpam: Libpam vulnerable to read hashed password |
| CVE-2024-22365   | pam: allowing unprivileged user to block another user namespace |
| CVE-2024-10041   | pam: libpam: Libpam vulnerable to read hashed password |
| CVE-2024-22365   | pam: allowing unprivileged user to block another user namespace |
| CVE-2024-10041   | pam: libpam: Libpam vulnerable to read hashed password |
| CVE-2024-22365   | pam: allowing unprivileged user to block another user namespace |
| CVE-2024-10041   | pam: libpam: Libpam vulnerable to read hashed password |
| CVE-2024-22365   | pam: allowing unprivileged user to block another user namespace |
| CVE-2021-4214    | libpng: hardcoded value leads to heap-overflow |
| CVE-2022-0563    | util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline |
| CVE-2024-5535    | openssl: SSL_select_next_proto buffer overread |
| CVE-2024-9143    | openssl: Low-level invalid GF(2^m) parameters lead to OOB memory access |
| CVE-2022-27943   | binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const |
| CVE-2023-4039    | gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 |
| CVE-2013-4392    | systemd: TOCTOU race condition when updating file permissions and SELinux security contexts |
| CVE-2023-31437   | An issue was discovered in systemd 253. An attacker can modify a seale ... |
| CVE-2023-31438   | An issue was discovered in systemd 253. An attacker can truncate a sea ... |
| CVE-2023-31439   | An issue was discovered in systemd 253. An attacker can modify the con ... |
| CVE-2023-52355   | libtiff: TIFFRasterScanlineSize64 produce too-big size and could cause OOM |
| CVE-2023-52356   | libtiff: Segment fault in libtiff  in TIFFReadRGBATileExt() leading to denial of service |
| CVE-2024-7006    | libtiff: NULL pointer dereference in tif_dirinfo.c |
| CVE-2023-25433   | libtiff: Buffer Overflow via /libtiff/tools/tiffcrop.c |
| CVE-2023-26965   | libtiff: heap-based use after free via a crafted TIFF image in loadImage() in tiffcrop.c |
| CVE-2023-26966   | libtiff: Buffer Overflow in uv_encode() |
| CVE-2023-2908    | libtiff: null pointer dereference in tif_dir.c |
| CVE-2023-3618    | libtiff: segmentation fault in Fax3Encode in libtiff/tif_fax3.c |
| CVE-2023-6277    | libtiff: Out-of-memory in TIFFOpen via a craft file |
| CVE-2017-16232   | libtiff: Memory leaks in tif_open.c, tif_lzw.c, and tif_aux.c |
| CVE-2017-17973   | libtiff: heap-based use after free in tiff2pdf.c:t2p_writeproc |
| CVE-2017-5563    | libtiff: Heap-buffer overflow in LZWEncode tif_lzw.c |
| CVE-2017-9117    | libtiff: Heap-based buffer over-read in bmp2tiff |
| CVE-2018-10126   | libtiff: NULL pointer dereference in the jpeg_fdct_16x16 function in jfdctint.c |
| CVE-2022-1210    | tiff: Malicious file leads to a denial of service in TIFF File Handler |
| CVE-2023-1916    | libtiff: out-of-bounds read in extractImageSection() in tools/tiffcrop.c |
| CVE-2023-3164    | libtiff: heap-buffer-overflow in extractImageSection() |
| CVE-2023-6228    | libtiff: heap-based buffer overflow in cpStripToTile() in tools/tiffcp.c |
| CVE-2023-50495   | ncurses: segmentation fault via _nc_wrap_entry() |
| CVE-2023-45918   | ncurses: NULL pointer dereference in tgetstr in tinfo/lib_termcap.c |
| CVE-2013-4392    | systemd: TOCTOU race condition when updating file permissions and SELinux security contexts |
| CVE-2023-31437   | An issue was discovered in systemd 253. An attacker can modify a seale ... |
| CVE-2023-31438   | An issue was discovered in systemd 253. An attacker can truncate a sea ... |
| CVE-2023-31439   | An issue was discovered in systemd 253. An attacker can modify the con ... |
| CVE-2022-0563    | util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline |
| CVE-2024-25062   | libxml2: use-after-free in XMLReader |
| CVE-2023-39615   | libxml2: crafted xml can cause global buffer overflow |
| CVE-2023-45322   | libxml2: use-after-free in xmlUnlinkNode() in tree.c |
| CVE-2024-34459   | libxml2: buffer over-read in xmlHTMLPrintFileContext in xmllint.c |
| CVE-2015-9019    | libxslt: math.random() in xslt uses unseeded randomness |
| CVE-2023-4641    | shadow-utils: possible password leak during passwd(1) change |
| CVE-2007-5686    | initscripts in rPath Linux 1 sets insecure permissions for the /var/lo ... |
| CVE-2023-29383   | shadow: Improper input validation in shadow-utils package utility chfn |
| TEMP-0628843-DBAD28 | [more related to CVE-2005-4890] |
| CVE-2022-0563    | util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline |
| CVE-2023-50495   | ncurses: segmentation fault via _nc_wrap_entry() |
| CVE-2023-45918   | ncurses: NULL pointer dereference in tgetstr in tinfo/lib_termcap.c |
| CVE-2023-50495   | ncurses: segmentation fault via _nc_wrap_entry() |
| CVE-2023-45918   | ncurses: NULL pointer dereference in tgetstr in tinfo/lib_termcap.c |
| CVE-2024-7347    | nginx: specially crafted MP4 file may cause denial of service |
| CVE-2009-4487    | nginx: Absent sanitation of escape sequences in web server log |
| CVE-2013-0337    | The default configuration of nginx, possibly 1.3.13 and earlier, uses  ... |
| CVE-2023-44487   | HTTP/2: Multiple HTTP/2 enabled web servers are vulnerable to a DDoS attack (Rapid Reset Attack) |
| CVE-2024-5535    | openssl: SSL_select_next_proto buffer overread |
| CVE-2024-9143    | openssl: Low-level invalid GF(2^m) parameters lead to OOB memory access |
| CVE-2023-4641    | shadow-utils: possible password leak during passwd(1) change |
| CVE-2007-5686    | initscripts in rPath Linux 1 sets insecure permissions for the /var/lo ... |
| CVE-2023-29383   | shadow: Improper input validation in shadow-utils package utility chfn |
| TEMP-0628843-DBAD28 | [more related to CVE-2005-4890] |
| CVE-2023-31484   | perl: CPAN.pm does not verify TLS certificates when downloading distributions over HTTPS |
| CVE-2011-4116    | perl: File:: Temp insecure temporary file handling |
| CVE-2023-31486   | http-tiny: insecure TLS cert default |
| TEMP-0517018-A83CE6 | [sysvinit: no-root option in expert installer exposes locally exploitable security flaw] |
| CVE-2005-2541    | tar: does not properly warn the user when extracting setuid or setgid files |
| TEMP-0290435-0B57B5 | [tar's rmt command may have undesired side effects] |
| CVE-2022-0563    | util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline |
| CVE-2022-0563    | util-linux: partial disclosure of arbitrary files in chfn and chsh when compiled with libreadline |
| CVE-2023-45853   | zlib: integer overflow and resultant heap-based buffer overflow in zipOpenNewFileInZip4_6 |
