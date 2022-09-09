<?php

class BilibiliLogin
{
    private $realip;
    private $userinfo;

    public function setRealIp($ip)
	{
		$this->realip = $ip;
	}

    /**
     * getAccessToken
     * @return mixed
     * @author BadCen
     */
    private function getAccessToken($cookie)
    {
        $url = 'https://passport.bilibili.com/login/app/third';
        $payload = [
            'appkey' => '27eb53fc9058f8c3',
            'api' => 'https://www.mcbbs.net/template/mcbbs/image/special_photo_bg.png',
            'sign' => '04224646d1fea004e79606d3b038c84a'
        ];
        $data  = $this->curl($url.'?'.http_build_query($payload), null, $cookie);
        $arr = json_decode($data, true);
        if(isset($arr['code']) && $arr['code']==0){
            $this->userinfo = $arr['data']['user_info'];
            $data = $this->curl($arr['data']['confirm_uri'], null, $cookie, true);
            preg_match("/access_key=(.*?)&/", $data['header'], $match);
            return $match[1];
        }
        return false;
    }

    /*
     * 获取极验参数
    */
    public function geetest()
    {
        $url = 'https://passport.bilibili.com/x/passport-login/captcha?source=main_mini&t=0.887951' . time();
        $ret = $this->curl($url);
        $arr = json_decode($ret, true);
        if(isset($arr['code']) && $arr['code']==0){
            return ['code' => 0, 'geetest' => $arr['data']['geetest'], 'token' => $arr['data']['token'] ];
        }else{
            return ['code' => -1, 'msg' => '获取极验参数失败 '.$arr['message'] ];
        }
    }

    /*
     * 加密登录密码
    */
    private function encrypted_password($password = null)
    {
        $url = 'https://passport.bilibili.com/x/passport-login/web/key?_=164' . time();
        $data = $this->curl($url);  //获取加密公钥及密码盐值1（web端）
        $arr = json_decode($data, true);
        openssl_public_encrypt($arr['data']['hash'] . $password, $encrypted, $arr['data']['key']);
        return base64_encode($encrypted);
    }

    /*
     * 账号密码登录
     */
    public function login($data)
    {
        $url = 'https://passport.bilibili.com/x/passport-login/web/login'; //使用账号密码登录（web端）
        $payload = [
            'source' => 'main_mini',
            'username' => $data['username'],
            'password' => $this->encrypted_password($data['password']),
            'keep' => 'true',
            'token'   => $data['key'],
            'go_url' => 'https://www.bilibili.com/',
            'challenge' => $data['geetest_challenge'],
            'validate' => $data['geetest_validate'],
            'seccode' => $data['geetest_seccode'],
        ];
        $raw = $this->curl($url, $payload, null, true);
        //print_r($raw);
        $arr = json_decode($raw['body'], true);
        if ($arr['data'] && $arr['data']['status'] == 0) {
            preg_match('/DedeUserID=(.*?)\;/', $raw['header'], $mid);
            preg_match('/DedeUserID__ckMd5=(.*?)\;/', $raw['header'], $mid_md5);
            preg_match('/SESSDATA=(.*?)\;/', $raw['header'], $token);
            preg_match('/bili_jct=(.*?)\;/', $raw['header'], $csrf);
            $cookie = 'DedeUserID=' . $mid[1] . '; ' . 'DedeUserID__ckMd5=' . $mid_md5[1] . '; ' . 'SESSDATA=' . $token[1] . '; ' . 'bili_jct=' . $csrf[1] . '; ';
            $data = ['mid'=>$mid[1], 'mid_md5'=>$mid_md5[1], 'token'=>$token[1], 'csrf'=>$csrf[1]];
            return array('code' => 0, 'msg' => '登录成功', 'data' => $data, 'cookie' => $cookie, 'uname'=>'UID:'.$mid[1]);
        } elseif ($arr['data'] && $arr['data']['status'] == 2) {
            if($arr['data']['url']){
                $query = parse_url($arr['data']['url'], PHP_URL_QUERY);
                parse_str($query, $riskurl);
                $tmptoken = $riskurl['tmp_token'];
                $requestid = $riskurl['requestId'];
                $raw = $this->curl('https://api.bilibili.com/x/safecenter/user/info?tmp_code='.$tmptoken);
                $arr = json_decode($raw, true);
                if(isset($arr['code']) && $arr['code']==0){
                    if($arr['data']['account_info']['tel_verify']){
                        return array('code' => -2, 'msg' => '为了您的账户安全，需要验证您的手机', 'tel' => $arr['data']['account_info']['hide_tel'], 'tmptoken'=>$tmptoken, 'requestid'=>$requestid);
                    }
                }else{
                    return array('code' => -1, 'msg' => '获取登录验证信息失败 '.$arr['message']);
                }
            }
            return array('code' => -1, 'msg' => '本次登录环境存在风险，请尝试使用扫码登录');
        } else {
            return array('code' => -1, 'msg' => $arr['message']);
        }
    }

    //登录异常，获取极验参数
    public function geetest2()
    {
        $url = 'https://passport.bilibili.com/web/captcha/combine?plat=5';
        $ret = $this->curl($url);
        $arr = json_decode($ret, true);
        if(isset($arr['code']) && $arr['code']==0){
            return ['code' => 0, 'data' => $arr['data']['result']];
        }else{
            return ['code' => -1, 'msg' => '获取极验参数失败 '.$arr['message'] ];
        }
    }

    //登录异常，发送短信验证码
    public function sendsms($data)
    {
        $url = 'https://api.bilibili.com/x/safecenter/sms/send';
        $post = [
            'type' => '17',
            'tmp_code' => $data['tmptoken'],
            'captcha_key' => $data['key'],
            'captcha_type' => '5',
            'challenge' => $data['geetest_challenge'],
            'seccode' => $data['geetest_seccode'],
            'validate' => $data['geetest_validate'],
        ];
        $raw = $this->curl($url, $post);
        $arr = json_decode($raw, true);
        if (isset($arr['code']) && $arr['code'] == 0) {
            return array('code' => 0, 'msg' => '短信验证码发送成功！');
        } else {
            return array('code' => -1, 'msg' => '短信验证码发送失败，'.$arr['message']);
        }
    }

    //登录异常，验证短信验证码并登录
    public function verifyLogin($data)
    {
        $url = 'https://api.bilibili.com/x/safecenter/tel/verify';
        $post = [
            'type' => '17',
            'code' => $data['code'],
            'tmp_code' => $data['tmptoken'],
            'request_id' => $data['requestid'],
        ];
        $raw = $this->curl($url, $post);
        $arr = json_decode($raw, true);
        if (isset($arr['code']) && $arr['code'] == 0) {
            $code = $arr['data']['code'];
            $url = 'https://passport.bilibili.com/web/sso/exchange_cookie?code='.$code;
            $raw = $this->curl($url, null, null, true);
            $de_raw = json_decode($raw['body'], true);
            if (isset($de_raw['code']) && $de_raw['code'] == 0) {
                preg_match('/DedeUserID=(.*?)\;/', $raw['header'], $mid);
                preg_match('/DedeUserID__ckMd5=(.*?)\;/', $raw['header'], $mid_md5);
                preg_match('/SESSDATA=(.*?)\;/', $raw['header'], $token);
                preg_match('/bili_jct=(.*?)\;/', $raw['header'], $csrf);
                $cookie = 'DedeUserID=' . $mid[1] . '; ' . 'DedeUserID__ckMd5=' . $mid_md5[1] . '; ' . 'SESSDATA=' . $token[1] . '; ' . 'bili_jct=' . $csrf[1] . '; ';
                $data = ['mid'=>$mid[1], 'mid_md5'=>$mid_md5[1], 'token'=>$token[1], 'csrf'=>$csrf[1]];
                return array('code' => 0, 'msg' => '登录成功', 'data' => $data, 'cookie' => $cookie, 'uname'=>'UID:'.$mid[1]);
            } else {
                return array('code' => -1, 'msg' => $de_raw['message']);
            }
        } else {
            return array('code' => -1, 'msg' => $arr['message']);
        }
    }

    //短信登录，发送短信验证码
    public function sendsms2($data)
    {
        $url = 'https://passport.bilibili.com/x/passport-login/web/sms/send';
        $post = [
            'tel' => $data['tel'],
            'cid' => '86',
            'source' => 'main_mini',
            'token' => $data['key'],
            'captcha_type' => '5',
            'challenge' => $data['geetest_challenge'],
            'validate' => $data['geetest_validate'],
            'seccode' => $data['geetest_seccode'],
        ];
        $raw = $this->curl($url, $post);
        $arr = json_decode($raw, true);
        if (isset($arr['code']) && $arr['code'] == 0) {
            return array('code' => 0, 'msg' => '短信验证码发送成功！', 'key' => $arr['data']['captcha_key']);
        } else {
            return array('code' => -1, 'msg' => '短信验证码发送失败，'.$arr['message']);
        }
    }

    //短信登录
    public function smsLogin($data)
    {
        $url = 'https://passport.bilibili.com/x/passport-login/web/login/sms';
        $payload = [
            'cid' => '86',
            'tel' => $data['tel'],
            'code' => $data['code'],
            'source' => 'main_mini',
            'go_url' => 'https://www.bilibili.com/',
            'keep' => 'true',
            'captcha_key' => $data['key'],
        ];
        $raw = $this->curl($url, $payload, null, true);
        //print_r($raw);
        $arr = json_decode($raw['body'], true);
        if ($arr['data'] && $arr['data']['status'] == 0) {
            preg_match('/DedeUserID=(.*?)\;/', $raw['header'], $mid);
            preg_match('/DedeUserID__ckMd5=(.*?)\;/', $raw['header'], $mid_md5);
            preg_match('/SESSDATA=(.*?)\;/', $raw['header'], $token);
            preg_match('/bili_jct=(.*?)\;/', $raw['header'], $csrf);
            $cookie = 'DedeUserID=' . $mid[1] . '; ' . 'DedeUserID__ckMd5=' . $mid_md5[1] . '; ' . 'SESSDATA=' . $token[1] . '; ' . 'bili_jct=' . $csrf[1] . '; ';
            $data = ['mid'=>$mid[1], 'mid_md5'=>$mid_md5[1], 'token'=>$token[1], 'csrf'=>$csrf[1]];
            return array('code' => 0, 'msg' => '登录成功', 'data' => $data, 'cookie' => $cookie, 'uname'=>'UID:'.$mid[1]);
        } else {
            return array('code' => -1, 'msg' => $arr['message']);
        }
    }


    //获取二维码
    public function getQrcode()
    {
        $url = 'https://passport.bilibili.com/qrcode/getLoginUrl';
        $raw = $this->curl($url);
        $de_raw = json_decode($raw, true);
        if (isset($de_raw['code']) && $de_raw['code'] == 0) {
            return array('code' => 0, 'msg' => '获取成功', 'url' => $de_raw['data']['url'], 'key' => $de_raw['data']['oauthKey']);
        } else {
            return array('code' => -1, 'msg' => '获取二维码失败，'.$de_raw['message']);
        }
    }

    //扫码登录
    public function qrLogin($key)
    {
        $url = 'http://passport.bilibili.com/qrcode/getLoginInfo';
        $payload = [
            'oauthKey' => $key
        ];
        $raw = $this->curl($url, $payload, null, true);
        $de_raw = json_decode($raw['body'], true);
        if ($de_raw['status'] == true) {
            preg_match('/DedeUserID=(.*?)\;/', $raw['header'], $mid);
            preg_match('/DedeUserID__ckMd5=(.*?)\;/', $raw['header'], $mid_md5);
            preg_match('/SESSDATA=(.*?)\;/', $raw['header'], $token);
            preg_match('/bili_jct=(.*?)\;/', $raw['header'], $csrf);
            $cookie = 'DedeUserID=' . $mid[1] . '; ' . 'DedeUserID__ckMd5=' . $mid_md5[1] . '; ' . 'SESSDATA=' . $token[1] . '; ' . 'bili_jct=' . $csrf[1] . '; ';
            $data = ['mid'=>$mid[1], 'mid_md5'=>$mid_md5[1], 'token'=>$token[1], 'csrf'=>$csrf[1]];
            return array('code' => 0, 'msg' => '登录成功', 'data' => $data, 'cookie' => $cookie, 'uname'=>'UID:'.$mid[1]);
        } else {
            if ($de_raw['data'] == -4) {
                return array('code' => 1, 'msg' => '请使用哔哩哔哩APP扫描二维码');
            } elseif ($de_raw['data'] == -5) {
                return array('code' => 2, 'msg' => '请在哔哩哔哩APP确认登录');
            } elseif ($de_raw['data'] == -2) {
                return array('code' => 3, 'msg' => '登录超时请重新获取二维码');
            } elseif ($de_raw['data'] == -1) {
                return array('code' => -1, 'msg' => '密钥错误');
            } else {
                return array('code' => -1, 'msg' => $de_raw['message']);
            }
        }
    }

    public function qq_getqrcode(){
		$url='https://ssl.ptlogin2.qq.com/ptqrshow?s=8&e=0&appid=716027609&type=1&t=0.492909'.time().'&daid=383&pt_3rd_aid=101135748';
		$refer='https://xui.ptlogin2.qq.com/cgi-bin/xlogin?appid=716027609&daid=383&style=33&login_text=%E7%99%BB%E5%BD%95&hide_title_bar=1&hide_border=1&target=self&s_url=https%3A%2F%2Fgraph.qq.com%2Foauth2.0%2Flogin_jump&pt_3rd_aid=101135748&pt_feedback_link=https%3A%2F%2Fsupport.qq.com%2Fproducts%2F77942%3FcustomInfo%3Dwww.bilibili.com.appid101135748&theme=2&verify_theme=';
		$data=$this->curl($url,0,0,true,$refer);
		preg_match('/qrsig=(.*?);/',$data['header'],$match);
		if($qrsig=$match[1]){
			preg_match('/\((.*?)\)/',$data['body'],$match);
			$arr = json_decode($match[1], true);
			return array('code'=>0,'qrsig'=>$qrsig,'qrcode'=>$arr['qrcode']);
		}
		else{
			return array('code'=>-1,'msg'=>'二维码获取失败');
		}
	}

	public function qq_qrlogin($qrsig){
		if(empty($qrsig))return array('code'=>-1,'msg'=>'qrsig不能为空');
		$url='https://ssl.ptlogin2.qq.com/ptqrlogin?u1=https%3A%2F%2Fgraph.qq.com%2Foauth2.0%2Flogin_jump&ptqrtoken='.$this->getqrtoken($qrsig).'&ptredirect=0&h=1&t=1&g=1&from_ui=1&ptlang=2052&action=4-1-'.time().'000&js_ver=22072900&js_type=1&login_sig=&pt_uistyle=40&aid=716027609&daid=383&pt_3rd_aid=101135748&';
		$refer='https://xui.ptlogin2.qq.com/cgi-bin/xlogin?appid=716027609&daid=383&style=33&login_text=%E7%99%BB%E5%BD%95&hide_title_bar=1&hide_border=1&target=self&s_url=https%3A%2F%2Fgraph.qq.com%2Foauth2.0%2Flogin_jump&pt_3rd_aid=101135748&pt_feedback_link=https%3A%2F%2Fsupport.qq.com%2Fproducts%2F77942%3FcustomInfo%3Dwww.bilibili.com.appid101135748&theme=2&verify_theme=';
		$ret = $this->curl($url,0,'qrsig='.$qrsig.'; ',false,$refer);
		if(preg_match("/ptuiCB\('(.*?)'\)/", $ret, $arr)){
			$r=explode("','",str_replace("', '","','",$arr[1]));
			if($r[0]==0){
				preg_match('/uin=(\d+)&/',$ret,$uin);
				$uin=$uin[1];
				$data=$this->curl($r[2],0,0,true,$refer);
				if($data['header'] && strpos($data['header'],'/oauth2.0/login_jump')) {
					$cookie='';
					preg_match_all('/Set-Cookie: (.*?);/i',$data['header'],$matchs);
					foreach ($matchs[1] as $val) {
						if(substr($val,-1)=='=')continue;
						$cookie.=$val.'; ';
					}
					preg_match('/p_skey=(.*?);/',$cookie,$pskey);
					$cookie = substr($cookie,0,-2);
                    $state = md5(microtime());
                    $url = 'https://graph.qq.com/oauth2.0/authorize';
                    $post = 'response_type=code&client_id=101135748&redirect_uri=https%3A%2F%2Fpassport.bilibili.com%2Flogin%2Fsnsback%3Fsns%3Dqq%26state%3D'.$state.'%26source%3Dnew_main_mini&scope=do_like%2Cget_user_info%2Cget_simple_userinfo%2Cget_vip_info%2Cget_vip_rich_info%2Cadd_one_blog%2Clist_album%2Cupload_pic%2Cadd_album%2Clist_photo%2Cget_info%2Cadd_t%2Cdel_t%2Cadd_pic_t%2Cget_repost_list%2Cget_other_info%2Cget_fanslist%2Cget_idollist%2Cadd_idol%2Cdel_idol%2Cget_tenpay_addr&state=authorize&switch=&from_ptlogin=1&src=1&update_auth=1&openapi=80901010&g_tk='.$this->getGTK($pskey[1]).'&auth_time='.time().'304&ui=E4077228-8A59-4020-A957-B5830A9509D3';
                    $data=$this->curl($url,$post,$cookie,true,$url);
                    preg_match("/Location: (.*?)\r\n/i", $data['header'], $match);
                    if($redirect_uri = $match[1]){
                        return array('code'=>0,'msg'=>'succ','uin'=>$uin,'redirect_uri'=>$redirect_uri,'state'=>$state);
                    }else{
                        return array('code'=>-1,'uin'=>$uin,'msg'=>'登录QQ成功，回调网站失败！');
                    }
				}else{
					return array('code'=>-1,'uin'=>$uin,'msg'=>'登录QQ成功，获取相关信息失败！');
				}
			}elseif($r[0]==65){
				return array('code'=>1,'msg'=>'二维码已失效。');
			}elseif($r[0]==66){
				return array('code'=>2,'msg'=>'二维码未失效。');
			}elseif($r[0]==67){
				return array('code'=>3,'msg'=>'正在验证二维码。');
			}else{
				return array('code'=>-1,'msg'=>$r[4]);
			}
		}else{
			return array('code'=>-1,'msg'=>$ret);
		}
	}

	public function qq_connect($redirect_uri, $state){
		if(empty($redirect_uri) || parse_url($redirect_uri, PHP_URL_HOST)!='passport.bilibili.com')return array('code'=>-1,'msg'=>'回调地址错误');
		if(empty($state))return array('code'=>-1,'msg'=>'state不能为空');
		$raw=$this->curl($redirect_uri,0,'_jct='.$state,true);
        if(strpos($raw['header'], 'DedeUserID=') && strpos($raw['header'], 'SESSDATA=')){
            preg_match('/DedeUserID=(.*?)\;/', $raw['header'], $mid);
            preg_match('/DedeUserID__ckMd5=(.*?)\;/', $raw['header'], $mid_md5);
            preg_match('/SESSDATA=(.*?)\;/', $raw['header'], $token);
            preg_match('/bili_jct=(.*?)\;/', $raw['header'], $csrf);
            $cookie = 'DedeUserID=' . $mid[1] . '; ' . 'DedeUserID__ckMd5=' . $mid_md5[1] . '; ' . 'SESSDATA=' . $token[1] . '; ' . 'bili_jct=' . $csrf[1] . '; ';
            $data = ['mid'=>$mid[1], 'mid_md5'=>$mid_md5[1], 'token'=>$token[1], 'csrf'=>$csrf[1]];
            return array('code' => 0, 'msg' => '登录成功', 'data' => $data, 'cookie' => $cookie, 'uname'=>'UID:'.$mid[1]);
        }else{
            preg_match("/<div style=.*?>(.*?)<br \/>/s", $raw['body'], $match);
            if($match[1]){
                return array('code'=>-1,'msg'=>$match[1]);
            }else{
                return array('code'=>-1,'msg'=>'登录QQ成功，获取哔哩哔哩登录信息失败！');
            }
        }
	}

	private function getqrtoken($qrsig){
        $len = strlen($qrsig);
        $hash = 0;
        for($i = 0; $i < $len; $i++){
            $hash += (($hash << 5) & 2147483647) + ord($qrsig[$i]) & 2147483647;
			$hash &= 2147483647;
        }
        return $hash & 2147483647;
    }
	private function getGTK($skey){
        $len = strlen($skey);
        $hash = 5381;
        for ($i = 0; $i < $len; $i++) {
            $hash += ($hash << 5 & 2147483647) + ord($skey[$i]) & 2147483647;
            $hash &= 2147483647;
        }
        return $hash & 2147483647;
    }

    public function wx_getqrcode(){
        $state = md5(microtime());
		$url = 'https://open.weixin.qq.com/connect/qrconnect?appid=wxafc256bf83583323&redirect_uri=https%3A%2F%2Fpassport.bilibili.com%2Flogin%2Fsnsback%3Fsns%3Dwechat%26state%3D'.$state.'%26source%3Dnew_main_mini&response_type=code&scope=snsapi_login&state=authorize';
		$ret = $this->curl($url);
		preg_match('!connect/qrcode/(.*?)\"!',$ret,$match);
		if($uuid = $match[1])
			return array('code'=>0,'uuid'=>$uuid,'imgurl'=>'https://open.weixin.qq.com/connect/qrcode/'.$uuid);
		else
			return array('code'=>1,'msg'=>'获取二维码失败');
	}
	public function wx_qrlogin($uuid, $last=null){
		if(empty($uuid))return array('code'=>-1,'msg'=>'uuid不能为空');
		$last=$last?'&last='.$last:null;
		$url='https://long.open.weixin.qq.com/connect/l/qrconnect?uuid='.$uuid.$last.'&_='.time().'000';
		$ret = $this->curl($url,null,null,false,'https://open.weixin.qq.com/connect/qrconnect');
		if(preg_match("/wx_errcode=(\d+);window.wx_code=\'(.*?)\'/", $ret, $match)){
			$errcode = $match[1];
			$code = $match[2];
			if($errcode == 408){
				return array('code'=>'1','msg'=>'二维码未失效');
			}elseif($errcode == 404){
				return array('code'=>'2','msg'=>'请在微信中点击确认即可登录');
			}elseif($errcode == 402){
				return array('code'=>'3','msg'=>'二维码已失效');
			}elseif($errcode == 405){
                $state = md5(microtime());
                $url = 'https://passport.bilibili.com/login/snsback?sns=wechat&state='.$state.'&source=new_main_mini&code='.$code.'&state=authorize';
                $raw=$this->curl($url,0,'_jct='.$state,true);
                if(strpos($raw['header'], 'DedeUserID=') && strpos($raw['header'], 'SESSDATA=')){
                    preg_match('/DedeUserID=(.*?)\;/', $raw['header'], $mid);
                    preg_match('/DedeUserID__ckMd5=(.*?)\;/', $raw['header'], $mid_md5);
                    preg_match('/SESSDATA=(.*?)\;/', $raw['header'], $token);
                    preg_match('/bili_jct=(.*?)\;/', $raw['header'], $csrf);
                    $cookie = 'DedeUserID=' . $mid[1] . '; ' . 'DedeUserID__ckMd5=' . $mid_md5[1] . '; ' . 'SESSDATA=' . $token[1] . '; ' . 'bili_jct=' . $csrf[1] . '; ';
                    $data = ['mid'=>$mid[1], 'mid_md5'=>$mid_md5[1], 'token'=>$token[1], 'csrf'=>$csrf[1]];
                    return array('code' => 0, 'msg' => '登录成功', 'data' => $data, 'cookie' => $cookie, 'uname'=>'UID:'.$mid[1]);
                }else{
                    preg_match("/<div style=.*?>(.*?)<br \/>/s", $raw['body'], $match);
                    if($match[1]){
                        return array('code'=>-1,'msg'=>$match[1]);
                    }else{
                        return array('code'=>-1,'msg'=>'登录微信成功，获取哔哩哔哩登录信息失败！');
                    }
                }
			}else{
				return array('code'=>-1,'msg'=>$ret);
			}
		}elseif($ret){
			return array('code'=>-1,'msg'=>$ret);
		}else{
			return array('code'=>1);
		}
	}

    private function curl($url,$data=null,$cookie=null,$split=false,$referer=null){
		$ch=curl_init();
		curl_setopt($ch,CURLOPT_URL,$url);
		$httpheader[] = "Accept: application/json";
		$httpheader[] = "Accept-Language: zh-CN,zh;q=0.8";
		$httpheader[] = "Connection: keep-alive";
        if(!$referer) $httpheader[] = "Origin: https://passport.bilibili.com";
		if($this->realip){
			$httpheader[] = "X-Real-IP: ".$this->realip;
			$httpheader[] = "X-Forwarded-For: ".$this->realip;
		}
		curl_setopt($ch, CURLOPT_HTTPHEADER, $httpheader);
		if($data){
			if(is_array($data)) $data=http_build_query($data);
			curl_setopt($ch,CURLOPT_POSTFIELDS,$data);
			curl_setopt($ch,CURLOPT_POST,1);
		}
		curl_setopt($ch,CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($ch,CURLOPT_SSL_VERIFYHOST, false);
		curl_setopt($ch,CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch,CURLOPT_CONNECTTIMEOUT, 10);
        if($referer){
            curl_setopt($ch,CURLOPT_REFERER, $referer);
        }else{
            curl_setopt($ch,CURLOPT_REFERER, 'https://passport.bilibili.com/login');
        }
        if($cookie){
            curl_setopt($ch,CURLOPT_COOKIE, $cookie);
        }
        if($split){
			curl_setopt($ch,CURLOPT_HEADER, true);
		}
		curl_setopt($ch,CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36 Edg/95.0.1020.44');
		$ret=curl_exec($ch);
        if ($split) {
			$headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
			$header = substr($ret, 0, $headerSize);
			$body = substr($ret, $headerSize);
			$ret=array();
			$ret['header']=$header;
			$ret['body']=$body;
		}
		curl_close($ch);
		return $ret;
	}
}