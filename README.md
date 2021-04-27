# NetScanner
Automatic scan the network hosts and get operation system, MAC address ... etc.


![](https://img.shields.io/badge/python-v3.5%2B-blue)
![](https://img.shields.io/badge/platform-Linux%20%7C%20MacOS-blue)
![](https://img.shields.io/badge/build-passing-green.svg)
![](https://img.shields.io/badge/license-GPL-blue.svg)
![](https://img.shields.io/badge/status-stable-green.svg)

### System Requirements
- Only for MacOS & Linux due to the limitation of packages

### Requirements Install
```bash
$ pip3 install -r requirements.txt
```

### Usage
Run the `net_scanner.py` as `root` for operation system detection
```bash
$ sudo python3 net_scanner.py
```
- No arguments needed

### TODO
- [ ] Dealing with functions
- [ ] Dealing with `multithread` while host scanning [[Ref1]](https://www.neuralnine.com/threaded-port-scanner-in-python/)
- [ ] Dealing with return back from the end of the process
- [ ] Should double check the host OS using `nmap.scan('<ip_address>', arguments='-O')` when `nmap3.nmap_os_detection` return `Null`
- [ ] Can `nmap.PortScannerAsync()` / `nmap.PortScannerYield()` work? [[Ref]](https://xael.org/pages/python-nmap-en.html)
    -  `nmap.PortScannerAsync()` seems not working with Python v3.8.2
- [ ] Scan over all ports using `host.all_protocols()` [[Ref]](https://blog.51cto.com/11555417/2112069)
- [ ] Nmap chaetsheet : https://technologyredefine.blogspot.com/2017/09/nmap-cheatsheet.html
- [ ] `import quene`


### Contribution
- [Me](https://github.com/jason19970210)
- [HuanyueTW](https://github.com/HuanyueTW)

### Release
- 0.1.0 - Initial release (2020-04-02)
