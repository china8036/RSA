<?php

/**
 * Rsa 加密 解密 demo
 * @author Wang [BBG]
 */
require_once 'src/Provider.php';

try {
    
    $rsa = new \Ryan\RSA\Provider('rsa.config.php');

    $str = '宝贝购 BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com BBG baobeigou.com 宝贝购BBG ';

//私钥加密
    $data = $rsa->privateKeyEncode($str);

    echo $data . '<br><br><br>';


//公钥解密
    $decode = $rsa->decodePrivateEncode($data);
    echo $decode . '<br><br><br>';


//公钥加密
    $pdata = $rsa->publicKeyEncode('Hello World ！, 世界 你好！');

    echo $pdata . '<br><br><br>';


//私钥解密
    $pdecode = $rsa->decodePublicEncode($pdata);
    echo $pdecode . '<br><br><br>';
    
} catch (Exception $exc) {
    echo $exc->getMessage();
}
