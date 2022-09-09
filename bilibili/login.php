<?php
error_reporting(0);

require 'login.class.php';
$login=new BilibiliLogin();
$realip = isset($_SERVER['HTTP_X_REAL_IP'])?$_SERVER['HTTP_X_REAL_IP']:$_SERVER['REMOTE_ADDR'];
$login->setRealIp($realip);
if($_GET['do']=='geetest'){
	$array=$login->geetest();
}elseif($_GET['do']=='login'){
	$array=$login->login($_POST);
}elseif($_GET['do']=='geetest2'){
	$array=$login->geetest2();
}elseif($_GET['do']=='sendsms'){
	$array=$login->sendsms($_POST);
}elseif($_GET['do']=='verifylogin'){
	$array=$login->verifyLogin($_POST);
}elseif($_GET['do']=='sendsms2'){
	$array=$login->sendsms2($_POST);
}elseif($_GET['do']=='smslogin'){
	$array=$login->smsLogin($_POST);
}elseif($_GET['do']=='getqrcode'){
	$array=$login->getQrcode();
}elseif($_GET['do']=='qrlogin'){
	$array=$login->qrLogin($_POST['key']);
}elseif($_GET['do']=='qq_getqrcode'){
	$array=$login->qq_getqrcode();
}elseif($_GET['do']=='qq_qrlogin'){
	$array=$login->qq_qrlogin($_GET['qrsig']);
}elseif($_GET['do']=='qq_connect'){
	$array=$login->qq_connect($_POST['redirect_uri'],$_POST['state']);
}elseif($_GET['do']=='wx_getqrcode'){
	$array=$login->wx_getqrcode();
}elseif($_GET['do']=='wx_qrlogin'){
	$array=$login->wx_qrlogin($_GET['uuid'],$_GET['last']);
}
echo json_encode($array);