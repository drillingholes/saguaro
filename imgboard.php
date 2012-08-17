<?php

session_start();
ob_start();

include "config.php";
include "strings_e.php";
include BOARD_TEMPLATE;

if (!$con = mysql_connect(SQLHOST, SQLUSER, SQLPASS))
	die(S_SQLCONF);

$db_id = mysql_select_db(SQLDB, $con); 
if (!$db_id)
	die(mysql_error());

if (!INSTALLED) {
	if (!table_exist(SQLBANS)) 
		create_ban_table();

	if (!table_exist(SQLADMIN)) 
		create_admin_table();

	if (!table_exist(SQLREP)) 
		create_reports_table();

	if (!table_exist(SQLLOG)) {
		create_post_table();
		updatelog();
		header("Location: ".PHP_SELF2);
	}
}

remove_expired_bans();
if (is_banned()) 
	die(banpage());

$validated = validate();
if (STAFF_ONLY && !$validated)
	die(S_STAFFONLY);

$mode = $_REQUEST['mode'];
if (trim($_POST['reason']))
	$mode = 'report';

if (ENABLE_OEKAKI)
	cleartempdir();

if (!$mode) {
	if (!file_exists(PHP_SELF2))
		updatelog();

	if (2CH_MODE && $_SERVER['PATH_INFO'])
		read_thread();

	header("Location: ".PHP_SELF2);
	die();
}

// goddamn this is gross
if ($mode == 'regist') {
	$upfile = $_FILES['upfile']['tmp_name'];
	$upname = $_FILES['upfile']['name'];

	if (isset($_POST['oefile'])) {
		if (!ENABLE_OEKAKI)
			error(S_NOOEKAKI);

		$name = $_POST['oefile'].'.png';
		$upfile = TMP_DIR.$name;
		if (!file_exists($upfile))
			error(S_NOFILE);

		$upname = OE_NAME;
		$oefix = array(
			$_POST['time'],
			$_POST['painter'],
			$_POST['srcfile']
		);
	}

	regist(	$_POST['name'],
		$_POST['email'],
		$_POST['sub'],
		$_POST['com'],
		$_POST['pwd'],
		$upfile,
		$upname,
		$_POST['resto'],
		$_POST['locked'],
		$_POST['sticky'],
		$_POST['cap'],
		$oefix
	);
}
else if ($mode == 'oe_paint') {
	if (!ENABLE_OEKAKI)
		error(S_NOOEKAKI);

	oe_paint(
		$_POST['oe_width'],
		$_POST['oe_height'],
		$_POST['oe_painter'],
		$_POST['resno'],
		$_POST['oe_anim'],
		$_POST['oe_selfy'],
		$_POST['oe_src']
	);
}
else if ($mode == 'oe_finish') {
	if (!ENABLE_OEKAKI)
		error(S_NOOEKAKI);

	oe_finish(
		$_GET['resto'],
		$_GET['painter'],
		$_GET['ip'],
		$_GET['time'],
		$_GET['src']
	);
}
else if ($mode == 'login') {
	valid(	$_POST['user'], 
		$_POST['pass'], 
		$_POST['token']
	);
	panel_mainpage();
}
else if ($mode == 'bans') {
	valid();
	managebans();
}
else if ($mode == 'reports') {
	valid();
	managereports($_POST['dismiss']);
}
else if ($mode == 'newuser') {
	valid();
	create_user(	
		$_POST['user'], 
		$_POST['pass'], 
		$_POST['level']
	);
}
else if ($mode == 'deluser') {
	valid();
	delete_user($_POST['id']);
}
else if ($mode == 'changelvl') {
	valid();
	change_level($_POST['user'], $_POST['level']);
}
else if ($mode == 'changepass') {
	valid();
	change_password(
		$_POST['oldpass'], 
		$_POST['newpass'], 
		$_POST['confirm']
	);
}
else if ($mode == 'rebuild') {
	if (!$validated) 
		error(S_WRONGPASS);

	updateall();
	valid();
	panel_mainpage();
}
else if ($mode == 'admin') {
	valid();
	panel_mainpage();
}
else if ($mode == 'logout') {
	if ($validated) 
		logout();
	else 
		valid();
}
else if ($mode == 'banall') {
	if (!isset($_GET['org'])) 
		error(S_BANWHAT);

	if (isset($_GET['t'])) 
		$t = $_GET['t'];
	else 
		$t = $_GET['org'];

	valid();
	banform($_GET['org'], 0, 0, $t);
}
else if ($mode == 'ban') {
	valid();
	banform('ip', $_GET['ip'], $_GET['post']);
}
else if ($mode == 'delall') {
	if (!$validated)
		valid();

	if ($_GET['token'] != $_SESSION['token'])
		error(S_CSRF);

	if (!isset($_GET['org'])) 
		error(S_DELWHAT);

	if (isset($_GET['ip']))
		$arg = $_GET['ip'];
	else
		$arg = $_GET['org'];

	delete_all($_GET['org'], $arg);
	manage('new');
}
else if ($mode == 'sticky') {
	if (!$validated)
		valid();

	if ($_GET['token'] != $_SESSION['token'])
		error(S_CSRF);

	sticky($_GET['t']);

	if (isset($_GET['modview']))
		header('Location: '.PHP_SELF3);
	else
		manage('threads');
}
else if ($mode == 'lock') {
	if (!$validated)
		valid();

	if ($_GET['token'] != $_SESSION['token'])
		error(S_CSRF);

	lock($_GET['t']);

	if (isset($_GET['modview']))
		header('Location: '.PHP_SELF3);
	else
		manage('threads');
}
else if ($mode == 'staffdel') {
	if (!$validated)
		valid();

	if ($_GET['token'] != $_SESSION['token'])
		error(S_CSRF);

	$_POST[$_GET['no']] = 'delete';
	usrdel(0, 0, 1);
	manage('new');
}
else if ($mode == 'manage') {
	if (!$validated)
		error(S_WRONGPASS);

	if (!isset($_GET['org']))
		manage('new');

	if (isset($_GET['ip'])) 
		$arg = $_GET['ip'];
	else if (isset($_GET['t'])) 
		$arg = $_GET['t'];

	if (!isset($_GET['page'])) 
		$_GET['page'] = 1;

	manage($_GET['org'], $_GET['page'], $arg);
}
else if ($mode == 'modview') {
	if (!$validated) 
		error(S_WRONGPASS);

	if (!isset($_GET['p']) && !isset($_GET['t'])) 
		$_GET['p'] = 1;

	if (isset($_GET['p'])) {
		if ($_GET['p'] == 'subback')
			update_subback();
		else
			updatelog($_GET['p'], 0);
	}
	else if (isset($_GET['t'])) {
		$r = (2CH_MODE) ? $_GET['r'] : '';
		updatethread($_GET['t'], 0, $r);
	}
}
else if	($mode == 'banish') {
	if (!$validated) 
		error(S_WRONGPASS);

	if ($_POST['token'] != $_SESSION['token'])
		error(S_CSRF);

	if (isset($_POST['banall'])) {
		ban_all(
		$_POST['org'],
		$_POST['banall'],
		$_POST['reason'],
		$_POST['bantype'],
		$_POST['length'],
		$_POST['increment'],
		$_POST['after'],
		$_POST['append']
		);
	}
	else {
		ban(
		$_POST['ip_to_ban'],
		$_POST['post'],
		$_POST['reason'],
		$_POST['bantype'],
		$_POST['length'],
		$_POST['increment'],
		$_POST['after'],
		$_POST['append']
		);
	}
	updateall();
	valid();
	managebans();
}
else if ($mode == 'delban') {
	if (!$validated) 
		error(S_WRONGPASS);

	delete_ban($_POST['id']);
	valid();
	managebans();
}
else if	($mode == 'banpage') {
	banpage();
}
else if ($mode == 'report') {
	report($_POST['no'], $_POST['reason']);
	header("Location: ".PHP_SELF2);
}
else if ($mode == 'usrdel') {
	if (!$validated) 
		$archive = 0;
	else
		$archive = $_POST['archive'];

	usrdel($_REQUEST['no'], $_POST['pwd'], 0, $archive);

	if (isset($_POST['modview']))
		header('Location: '.PHP_SELF3);
	else
		header('Location: '.PHP_SELF2);
}
else
	error(S_NOTASK);

// build page caches
function updatelog($page = 0, $cache = 1) {
	if (STAFF_ONLY) $cache = 0;

	$threads = array();
	$posts = array();

	// stolen from wakaba
	$query = "SELECT * FROM ".SQLLOG." ORDER BY sticky DESC, root DESC, CASE resto WHEN 0 THEN no ELSE resto END ASC, no ASC";
	if (!$result = mysql_call($query))
		echo S_SQLFAIL;

	while ($row = mysql_fetch_assoc($result)) {
		if ($row['resto'])
			$tno = $row['resto'];
		else {
			$tno = $row['no'];
			$subs[$tno]['sub'] = $row['sub'];
		}

		$subs[$tno]['count']++;
		$posts[$tno][] = $row;
	}

	foreach ($posts as $thread) {
		$threads[] = $thread;
	}

	$threadcount = count($threads);
	if (!empty($threads)) {
		if (2CH_MODE) {
			$allpages = 1;
			update_subback($subs);
		}
		else {
			$allpages = $threadcount / PAGE_DEF;
			$allpages = ceil($allpages);
		}
		for ($i = 1; $i <= $allpages; $i++) {
			if (!$cache && $i < $page)
				continue;

			$tree = array();
			if ($i > 1) {
				$endlimit = PAGE_DEF * $i;
				$frontlimit = $endlimit - PAGE_DEF;
			}
			else {
				$endlimit = PAGE_DEF;
				$frontlimit = 0;
			}
			for ($j = $frontlimit; $j < $endlimit; $j++) {
				if (isset($threads[$j]))
					$tree[] = $threads[$j];
			}
			$dat = template($cache, $tree, 0, $i, $allpages);
			printpage($cache, $dat, 0, $i);

			if (!$cache) break;
		}
	}
	else {
		$dat = template($cache);
		printpage($cache, $dat, 0, 1);
	}
}

function updatethread($resno, $cache = 1, $ranges) {
	if (STAFF_ONLY) $cache = 0;

	$threads = array();
	$posts = array();

	$query = "SELECT * FROM ".SQLLOG." WHERE no=%s OR resto=%s ORDER BY no ASC"; 
	if (!$result = mysql_prepare($query, $resno, $resno))
		die(mysql_error());

	while ($postrow = mysql_fetch_assoc($result)) {
		$posts[] = $postrow;
	}

	if (empty($posts))
		error(S_REPORTERR);
	else {
		if (2CH_MODE && $ranges)
			$posts = filter_post_ranges($posts, $ranges);

		$threads[] = $posts;
		$dat = template($cache, $threads, $resno);
		printpage($cache, $dat, $resno, 0);
	}
}

function printpage($cache = 1, $dat, $resno, $page) {
	if ($resno) {
		$logfilename = RES_DIR.$resno.'.html';
	}
	else if ($page) {
		if ($page == 'subback')
			$logfilename = SUBBACK;
		else if ($page > 1)
			$logfilename = $page.'.html';
		else
			$logfilename = PHP_SELF2;
	}

	if ($cache) {
		$fp = fopen($logfilename, "w");
		set_file_buffer($fp, 0);
		rewind($fp);
		fputs($fp, $dat);
		fclose($fp);
		chmod($logfilename, 0666);
	}
	else {
		echo $dat;
		die();
	}
}

function mysql_call($query) {
	$ret = mysql_query($query);
	if (!$ret) {
		echo $query."<br />";
		echo mysql_errno().": ".mysql_error()."<br />";
	}
	return $ret;
}

// ghettorigged prepared statements
// TODO: replace this with PDO
function mysql_prepare() {
	$args = func_get_args();
	$query = array_shift($args);

	$count = count($args);
	for ($i = 0; $i < $count; $i++) {
		$args[$i] = mysql_real_escape_string($args[$i]);
		if (!is_int($args[$i]))
			$args[$i] = "'".$args[$i]."'";
	}

	array_unshift($args, $query);
	$query = call_user_func_array('sprintf', $args);
	$ret = mysql_query($query);
	return $ret;
}

function truncate($string, $resno, $modview) {
	$lines = explode('<br />', $string);
	if (count($lines) > MAX_LINES_SHOWN) {
		$lines = array_slice($lines, 0, MAX_LINES_SHOWN);
		$string = implode('<br />', $lines);
		if ($modview)
			$url = PHP_SELF3."&t=$resno";
		else if (2CH_MODE)
			$url = PHP_SELF."/$resno";
		else
			$url = RES_DIR.$resno.'.html';
		$string .= '<br /><br />';
		$string .= '<span class="abbr">Comment too long. Click ';
		$string .= '<a href="'.$url.'">here</a> ';
		$string .= 'to view the full text.</span>';
	}
	return $string;
}

function oe_info($anim, $params) {
	if (!is_int($params[0])) error(S_UNUSUAL);

	if ($params[0] < 0)
		error(S_UNUSUAL);
	else if ($params[0] < 60) 
		$time = $params[0].' s';
	else if ($params[0] < 3600)
		$time = round($params[0]/60).' min';
	else if ($params[0] < 3600 * 24 * 7) {
		$hours = floor($params[0]/3600);
		$mins  = round(($params[0]%3600)/60);
		$time  = "$hours h, $mins min";
	}
	else
		error(S_UNUSUAL);

	if ($params[1] == 'shi')
		$painter = 'Shi-Painter Normal';
	else if ($params[1] == 'shipro')
		$painter = 'Shi-Painter Pro';
	else
		error(S_OEUNKNOWN);

	if ($params[2]) {
		if (!file_exists(IMG_DIR.$params[2]))
			error(S_NOFILE);

		$url = IMG_DIR.$params[2];
		$src = ", Source: <a href=\"$url\">".$params[2]."</a>";
	}

	if ($anim) {
		$url = IMG_DIR.$anim.'.pch';
		$anim = ", Animation: <a href=\"$url\">View</a>";
	}

	$oeline = "<br /><br /><b>Oekaki post</b> (";
	$oeline .= "Time: $time, Painter: $painter$anim$src)";

	return $oeline;
}

function oe_paint($oekw, $oekh, $painter, $resno = 0, $anim, $selfy, $src = 0) {
	if (!is_int($oekw) || !is_int($oekh))
		error(S_NO);

	if ($oekw > MAX_OEKAKI_WIDTH || $oekh > MAX_OEKAKI_HEIGHT)
		error(S_TOOBIG);

	if ($oekw < MIN_OEKAKI_WIDTH || $oekh < MIN_OEKAKI_HEIGHT)
		error(S_TOODAMNSMALL);

	if ($src && !file_exists(IMG_DIR.$src))
		error(S_NOFILE);

	if ($painter != 'shi' && $painter != 'shipro')
		error(S_OEKUNKNOWN);

	$ip = $_SERVER['REMOTE_ADDR'];

	include PAINT_TEMPLATE;
	die();
}

function openpch($pch) {
	$pchfile = IMG_DIR.$pch.'.pch';
	if (!file_exists($pchfile))
		error(S_NOFILE);

	$viewanimation = 1;
	include PAINT_TEMPLATE;
	die();
}

function oe_finish($resto, $painter, $ip, $time, $src) {
	if (!preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/', $ip))
		error(S_BADIP);

	$tmpname = TMP_DIR.$ip.'.png';
	if (!$endtime = stat($tmpname))
		error(S_NOFILE);

	$time = $time - $endtime['mtime'];

	if ($painter != 'shi' && $painter != 'shipro')
		error(S_OEKUNKNOWN);

	if ($src && !file_exists(IMG_DIR.$src))
		error(S_NOFILE);

	$oearray = array($ip, $time, $painter, $src);
	head($dat);
	form($dat, $resno, $validated, $oearray);
	die($dat);
}

function regist($name, $email, $sub, $com, $pwd, $upfile, $upname, $resto, $locked, $sticky, $cap, $oe) {
	global $validated;

	if (BL_CHECK) blacklist_check();

	check_spam_fields();

	$time = time();
	$tim = $time.substr(microtime(), 2, 3);
	$ip = $_SERVER['REMOTE_ADDR'];

	if (preg_match("/[\r\n]/", $name)) error(S_UNUSUAL);
	if (preg_match("/[\r\n]/", $email)) error(S_UNUSUAL);
	if (preg_match("/[\r\n]/", $sub)) error(S_UNUSUAL);

	if (strlen($name) > 100) error(S_TOOLONG);
	if (strlen($email) > 100) error(S_TOOLONG);
	if (strlen($sub) > 100) error(S_TOOLONG);
	if (strlen($com) > 10000) error(S_TOOLONG);

	if ($upfile && !USE_IMAGES)
		error(S_IMAGE);

	if ($resto) {
		if (locked($resto))
			error(S_LOCKED);

		if (PERMASAGE || AUTOLOCK) 
			$count = threadcount($resto);

		if (PERMASAGE && $count >= PERMASAGE) 
			$sage = 1;

		if (AUTOLOCK && $count >= AUTOLOCK) {
			if (!$validated) lock($resto);
		}
	}

	if ($validated) {
		if ($cap) $cap = ($validated > 1) ? ACAPCODE : MCAPCODE;

		if ($resto) $locked = $sticky = 0;
	}
	else {
		if ($sticky || $locked || $cap)
			error(S_NOTAMOD);

		if (!$resto) {
			if (!$upfile || !file_exists($upfile))
				error(S_NEEDIMAGE);
		}

		if (CAPCHA_ON)
			checkcaptcha();
	}

	if (!trim($com) && !file_exists($upfile)) 
		error(S_NOTEXT);

	if (!trim($name) || FORCED_ANONYMOUS) 
		$name = S_ANONAME;
	else
		$name = process_tripcode($name);

	$name = $name.$cap;

	if ($email == 'noko') {
		$noko = 1;
		$email = '';
	}

	if ($email == 'sage') 
		$sage = 1;

	if (trim($email)) {
		if (FORCED_ANONYMOUS) 
			$email = '';
		else 
			$email = cleanstring($email);
	}

	if (!trim($sub)) 
		$sub = S_ANOTITLE;
	else 
		$sub = cleanstring($sub);

	if (!trim($com)) 
		$com = S_ANOTEXT;
	else
		$com = cleanstring($com, 1);

	if ($upfile) $md5 = md5_file($upfile);

	if (!$validated) {
		$query = "SELECT max(no) FROM ".SQLLOG;
		if (!$result = mysql_call($query))
			die(mysql_error());

		$maxno = mysql_fetch_row($result);
		$lastno = $maxno[0];

		flood_check(
			$time, $md5, $ip, 
			$lastno, $com, $resto
		);
	}

	$date = date(DATE_STYLE, $time);

	if (!trim($pwd)) 
		$pwd = rand();

	$pass = crypt($pwd);

	if ($upfile) {
		$filesize = filesize($upfile);
		if ($filesize > MAX_KB * 1024) error(S_TOOBIG);
		$attributes = process_file($upfile, $upname, $tim);
		list ($w, $h, $ext, $tw, $th) = $attributes;

		$upname = cleanstring($upname);
		if (strlen($upname) > 50)
			$upname = substr($upname, 0, 48).'...';
	}

	if ($oe) {
		$pch = TMP_DIR.$ip.'.pch';
		if (file_exists($pch)) {
			$anim = $tim;
			rename($pch, IMG_DIR.$tim.'.pch');
			chmod(IMG_DIR.$tim.'.pch', 0666);
		}
		$com .= oe_info($anim, $oe);
	}

	$rootqu = "0";
	if (!$resto) {
		$rootqu = "now()";
		trim_db();
	}
	else if (!$sage) {
		$query = "UPDATE ".SQLLOG." SET root=now() WHERE no=%s";
		if (!mysql_prepare($query, $resto))
			die(mysql_error());
	}

	$query = "
	INSERT INTO ".SQLLOG." VALUES(".
		"null,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,".
		"%s,%s,%s,%s,%s,%s,%s,%s,$rootqu,%s,%s".
	")";

	$result = mysql_prepare(
		$query, $date, $name, $email, $sub, $com, $ip, 
		$pass, $ext, $w, $h, $tw, $th, $tim, $time, $md5, 
		$upname, $filesize, $locked, $sticky, $resto, ''
	);

	if (!$result) die(mysql_error());

	if (!$resto) $resto = mysql_insert_id();

	if ($upfile) {
		if ($oe) rename($upfile, IMG_DIR.$tim.$ext);

		else move_uploaded_file($upfile, IMG_DIR.$tim.$ext);
	}

	setcookie("namec", implode('#', $nameparts), time()+7*24*3600);
	setcookie("emailc", $email, time()+7*24*3600);
	setcookie("pwdc", $pwd, time()+7*24*3600);

	ob_flush();

	if (!STAFF_ONLY) {
		if (!2CH_MODE)
			updatethread($resto);

		updatelog();
	}

	if ($noko) {
		if (isset($_POST['modview']))
			$redirect = PHP_SELF3.'&t='.$resto;
		else if (2CH_MODE)
			$redirect = PHP_SELF."/$resto/l50";
		else
			$redirect = RES_DIR.$resto.".html";
	}

	else {
		if (isset($_POST['modview']))
			$redirect = PHP_SELF3;
		else
			$redirect = PHP_SELF2;
	}

	header('Location: '.$redirect);
	flush();
}

function blacklist_check() {
	if (TOR_BLOCK) {
		$ip = explode('.', $_SERVER['REMOTE_ADDR']);
		$servip = explode('.', $_SERVER['SERVER_ADDR']);
		$ip = implode('.', array_reverse($ip));
		$servip = implode('.', array_reverse($servip));

		$address = $ip.'.'.$_SERVER['SERVER_PORT'].'.'.$servip.'.ip-port.exitlist.torproject.org';
		$lookup = gethostbyname($address);

		if (strpos($lookup, '127.0.0'))
			error(S_BL);
	}

	if (RBL_CHECK) {
		if (!$ip) {
			$ip = explode('.', $_SERVER['REMOTE_ADDR']);
			$ip = implode('.', array_reverse($ip));
		}
		$rbls = explode('|', RBL_CHECK);
		foreach ($rbls as $rbl) {
			$lookup = gethostbyname($ip.'.'.$rbl);
			if (strpos($lookup, '127.0.0'))
				error(S_BL);
		}
	}
}

function check_spam_fields() {
	$spam = explode('|', SPAM_FIELDS);
	foreach ($spam as $field) {
		if (!empty($_POST[$field]))
			error(S_SPAM);
	}

	if (SPAM_FILE) {
		$fields = array('com', 'email', 'sub', 'name');
		$spamdefs = file(SPAM_FILE);
		$pattern = '/'
		foreach ($spamdefs as $spamdef) {
			if (!preg_match('/\/(.*)\//', $spamdef))
				$spamdef = preg_quote($spamdef, '/');

			$pattern .= $end.$spamdef;
			$end = '|';
		}
		$pattern = substr($pattern, 0, -1).'/i';
		foreach ($fields as $field) {
			if (preg_match($pattern, $_POST[$field]))
				error(S_SPAM);
		}
	}
}

function locked($thread) {
	global $validated;

	$query = "SELECT no,locked FROM ".SQLLOG." WHERE no=%s";
	if (!$result = mysql_prepare($query, $thread))
		die(mysql_error());

	if (!$threadnum = mysql_fetch_assoc($result))
		error(S_NOTHREADERR);
	else {
		if ($validated) return 0;
		if ($threadnum['locked']) return 1;
	}
}

function threadcount($thread) {
	$query = "SELECT count(*) FROM ".SQLLOG." WHERE resto=%s";
	if (!$result = mysql_prepare($query, $thread))
		die(S_SQLFAIL);

	$row = mysql_fetch_row($result);
	return $row[0];
}

function check_captcha() {
	if (CAPTCHA_ON == 1) {
		include 'recaptchalib.php';
		$resp = recaptcha_check_answer(	
			PRIVATE_KEY, $_SERVER['REMOTE_ADDR'], 
			$_POST['recaptcha_challenge_field'], 
			$_POST['recaptcha_response_field']
		);

		if (!$resp->is_valid)
			error(S_WRONGCAPTCHA);
	}
	else if (CAPTCHA_ON == 2) {
		$capkey = substr($_SESSION['capkey'], 0, 5);
		if ($_POST['num'] != $capkey)
			error(S_WRONGCAPTCHA);
	}
}

function process_tripcode($name) {
	$name = str_replace('&#', '&%', $name);
	$nameparts = str_replace('&%', '&#', explode('#', $name));
	$nameparts[0] = cleanstring($nameparts[0]);
	if (trim($nameparts[1])) {
		$salt = substr($nameparts[1]."H.", 1, 2);
		$salt = preg_replace("/[^\.-z]/", ".", $salt);
		$salt = strtr($salt, ":;<=>?@[\\]^_`", "ABCDEFGabcdef");
		$regtrip = "!".substr(crypt($nameparts[1], $salt),-10);
	}
	if (trim($nameparts[2])) {
		$sha = base64_encode(pack("H*", sha1($nameparts[2].SALT)));
		$sha = substr($sha, 0, 11);
		$sectrip = "!!".$sha;
	}
	$trip = $regtrip.$sectrip;
	$name = $nameparts[0].'</b>'.$trip;
}

function process_file($upfile, $upname, $tim) {
	if ($size = getimagesize($upfile)) {
		$width = $size[0];
		$height = $size[1];

		if ($width > REJECT_W || $height > REJECT_H) 
			error(S_TOOBIG);

		if ($width < MIN_W || $width < MIN_H) 
			error(S_TOODAMNSMALL);

		switch ($size[2]) {
			case 1 : $ext = ".gif"; break;
			case 2 : $ext = ".jpg"; break;
			case 3 : $ext = ".png"; break;
			default : error(S_BADFILEISBAD);
		}

		$dims = thumb($upfile, $tim, $ext, $width, $height);
	}
	else {
		$ext = pathinfo($upname, PATHINFO_EXTENSION);
		$allowed = unserialize(ALLOWED_FILETYPES);
		if (!isset($allowed[$ext]))
			error(S_BADFILEISBAD);

		$type = mimetype($upfile);
		if ($type != $allowed[$ext][0])
			error(S_BADFILEISBAD);

		// dumb but necessary
		copy($allowed[$ext][1], THUMB_DIR.$tim.'s'.$ext);
		$width = $height = 0;
		$dims[0] = imagesx($allowed[$ext][1]);
		$dims[1] = imagesy($allowed[$ext][1]);
	}

	$ret = array(
		$width, $height, $ext, 
		$dims[0], $dims[1]
	);
	return $ret;
}

// php i fucking hate you you pile of shit
function mimetype($upfile) {
	if (function_exists('finfo_open')) {
		// this will most likely break on windows
		$finfo = finfo_open(FILEINFO_MIME_TYPE);
		$mime = finfo_file($finfo, $upfile);
		finfo_close($finfo);
		if ($mime)
			return $mime;
	}
	if (function_exists('mime_content_type')) {
		// this too
		$mime = mime_content_type($upfile);
		if ($mime)
			return $mime;
	}

	// try and sniff out the mime type ourselves
	// TODO: kill myself
	include 'extras/mime_magic_data.php';
	$f = fopen($upfile, 'rb');
	$contents = fread($f, 3072);
	fclose($f);

	foreach ($mime_magic_data as $def) {
		if ($def[0] >= 3072)
			continue;

		$slice = substr($contents, $def[0], $def[1]);
		if ($def[2]) {
			$value = hexdec(bin2hex($slice));
			if (($value & $def[2]) == $def[3])
				return $def[4];
		}
		else {
			if ($slice == $def[3])
				return $def[4];
		}
	}

	// fuck it
	return 'application/octet-stream'; 
}	

function flood_check($time, $md5, $ip, $lastno, $com, $resto) {
	if ($md5) {
		$floodtime = $time - RENZOKU2;
		$query = "SELECT time FROM ".SQLLOG." WHERE time>%s AND host=%s";
		if (!$result = mysql_prepare($query, $floodtime, $ip))
			echo S_SQLFAIL;

		if ($flooding = mysql_fetch_row($result))
			error(S_RENZOKU2);

		$where = "md5='$md5'";
		if (!DUPE_CHECK)
			$where = "com=%s AND ".$where;

		if (!$result = mysql_prepare("SELECT time FROM ".SQLLOG." WHERE $where", $com))
			echo S_SQLFAIL;

		if ($dupetime = mysql_fetch_row($result))
			error(S_DUPE);
	}
	else {
		$floodtime = $time - RENZOKU;
		$query = "SELECT time FROM ".SQLLOG." WHERE time>%s AND host=%s";
		if (!$result = mysql_prepare($query, $floodtime, $ip))
			echo S_SQLFAIL;

		if ($flooding = mysql_fetch_row($result))
			error(S_RENZOKU3);

		$last20 = $lastno - 20;
		$query = "SELECT time FROM ".SQLLOG." WHERE com=%s AND host=%s and no>%s";
		if (!$result = mysql_prepare($query, $com, $ip, $last20))
			echo S_SQLFAIL;

		if ($flooding = mysql_fetch_row($result))
			error(S_RENZOKU3);
	}

	if (MAX_THREADS_PER_MIN != 0 && !$resto) {
		list ($threads, $minutes) = explode('|', MAX_THREADS_PER_MIN);
		$floodtime = $time - ($minutes * 60);
		$query = "SELECT count(*) FROM ".SQLLOG." where resto=0 AND time>$floodtime";
		$result = mysql_query($query);
		$row = mysql_fetch_row($result);
		if ($row[0] >= $threads) 
			error(S_RENZOKU3);
	}
}

function cleanstring($string, $comment) {
	global $validated;

	$string = trim($string);
	$string = iconv("UTF-8", "UTF-8//IGNORE", $string);
	if (!$validated)
		$string = htmlspecialchars($string, ENT_QUOTES, 'UTF-8');
	else
		$string = modformat($string);

	if ($comment)
		$string = nl2br($string);

	return $string;
}

function modformat($com) {
	$com = preg_replace("/(^|\n)(>)([^>](.*))/m", "$1&gt;$3", $com);

	$regex = (2CH_MODE) ? "{(?:[0-9\-,l]|,)*[0-9\-l]}" : "[0-9]+";
	$com = preg_replace("/(>>)($regex)/", "&gt;&gt;$2", $com);

	return $com;
}

function trim_db() {
	$max = LOG_MAX - 1;
	// this bullshit hack brought to you by the mysql reference manual
	$query = "SELECT no FROM ".SQLLOG." WHERE root>0 AND sticky=0 ORDER BY root DESC LIMIT $max, 18446744";
	if (!$result = mysql_call($query))
		die(S_SQLFAIL);

	while ($row = mysql_fetch_assoc($result)) {
		$_POST[$row['no']] = 'delete';
		usrdel($row['no'], '', 1, ARCHIVE);
	}
}

function thumb($upfile, $tim, $ext, $w, $h) {
	if ($w > MAX_W || $h > MAX_H) {
		$key_w = MAX_W / $w;
		$key_h = MAX_H / $h;
		($key_w < $key_h) ? $keys = $key_w : $keys = $key_h;
		$out_w = ceil($w * $keys) +1;
		$out_h = ceil($h * $keys) +1;
	}
	else {
		$out_w = $w;
		$out_h = $h;
	}

	$dims = array($out_w, $out_h);

	if (THUMBMETHOD == 2)
		im_thumb($upfile, $tim, $ext, $out_w, $out_h);
	else
		gd_thumb($upfile, $tim, $ext, $w, $h, $out_w, $out_h);

	return $dims;
}

function im_thumb($upfile, $tim, $ext, $out_w, $out_h) {
	if (ANIMATED_THUMBS && $ext == '.gif')
		$do = '-coalesce -sample';
	else
		$do = '-resize';

	$src = escapeshellarg($upfile);
	$dst = escapeshellarg(THUMB_DIR.$tim.'s'.$ext);
	$quality = THUMBNAIL_QUALITY;

	$shell = "convert $src $do {$out_w}x{$out_h} -quality $quality $dst";
	exec($shell);
}

function gd_thumb($upfile, $tim, $ext, $width, $height, $out_w, $out_h) {
	if ($ext == '.gif')
		$im_in = imagecreatefromgif($upfile);
	else if ($ext == '.jpg')
		$im_in = imagecreatefromjpeg($upfile);
	else if ($ext == '.png')
		$im_in = imagecreatefrompng($upfile);

	if (!$im_in) return;

	$im_out = imagecreatetruecolor($out_w, $out_h);
	if ($ext == '.gif' || $ext == '.png') {
		$transparency = imagecolortransparent($im_in);
		if ($transparency >= 0) {
			$color = imagecolorsforindex($im_in, $transparency);
			$trasparency = imagecolorallocate(
				$im_out, $color['red'], 
				$color['green'], $color['blue']
			);
			imagefill($im_out, 0, 0, $transparency);
			imagecolortransparent($im_out, $transparency);
			if ($ext == '.gif') {
				$totalcolors = imagecolorstotal($im_in);
				imagetruecolortopalette($im_out, true, $totalcolors);
			}
		}
		else if ($ext == '.png') {
			imagealphablending($im_out, false);
			$bl = imagecolorallocatealpha($im_out, 0, 0, 0, 127);
			imagefill($im_out, 0, 0, $bl);
			imagesavealpha($im_out, true);
		}
	}
			
	imagecopyresampled(
		$im_out, $im_in, 0, 0, 0, 0, 
		$out_w, $out_h, $width, $height
	);

	if ($ext == '.gif')
		imagegif($im_out, THUMB_DIR.$tim.'s'.$ext);
	else if ($ext == '.jpg')
		imagejpeg($im_out, THUMB_DIR.$tim.'s'.$ext, 75);
	else if ($ext == '.png')
		imagepng($im_out, THUMB_DIR.$tim.'s'.$ext);

	chmod(THUMB_DIR.$tim.'s'.$ext, 0666);

	imagedestroy($im_in);
	imagedestroy($im_out);
}

function table_exist($table) {
	$result = mysql_call("show tables like '$table'");
	if (!$result) 
		return 0;

	$a = mysql_fetch_row($result);
	mysql_free_result($result);
	return $a;
}

function usrdel($no, $pwd, $automated = 0, $archive) {
	global $path, $validated;

	if (2CH_MODE) $archive = 0;

	$host = $_SERVER["REMOTE_ADDR"];
	$delno = array();
	reset($_POST);
	// this is from futallaby, i didnt write this
	while ($item = each($_POST)){
		if ($item[1] == 'delete')
			array_push($delno, $item[0]);
	}

	$countdel = count($delno);

	$updated = array();
	for ($i = 0; $i < $countdel; $i++) {
		$query = "select no,ext,tim,pwd,host,resto from ".SQLLOG." where no=%s";
		if (!$result = mysql_prepare($query, $delno[$i]))
			die(S_SQLFAIL);

		if (!$resrow = mysql_fetch_row($result))
			die(S_SQLFAIL);

		list ($dno,$dext,$dtim,$dpass,$dhost,$dresto) = $resrow;

		if (!checkpass($pwd, $dpass, $automated))
			error(S_BADDELPASS);

		$delfile = IMG_DIR.$dtim.$dext;
		$delthumb = THUMB_DIR.$dtim.'s'.$dext;

		if (!isset($_POST['onlyimgdel'])){
			if (!$dresto) {
				$deleted = 1;
				$query = "SELECT tim,ext FROM ".SQLLOG." WHERE resto=".$dno;
				if (!$result = mysql_call($query))
					die(S_SQLFAIL);

				while ($imgrow = mysql_fetch_row($result)) {
					list ($reptim, $repext) = $imgrow;
					$repdelfile = IMG_DIR.$reptim.$repext;
					$repthumb = THUMB_DIR.$reptim.'s'.$repext;

					if ($archive) {
						rename($repdelfile, ARC_DIR.$repdelfile);
						rename($repthumb, ARC_DIR.$repthumb);
					}
					else {
						unlink($repdelfile);
						unlink($repthumb);
					}
				}

				if ($archive) {
					rename($delfile, ARC_DIR.$delfile);
					rename($delthumb, ARC_DIR.$delthumb);
					rename(RES_DIR.$dno.'.html', ARC_DIR.RES_DIR.$dno.'.html');
				}
				else
					unlink(RES_DIR.$dno.'.html');

				$query = "DELETE FROM ".SQLLOG." WHERE resto=".$dno;
				if (!mysql_call($query))
					die(S_SQLFAIL);
	    		}

			if (!mysql_call("delete from ".SQLLOG." where no=".$dno))
				die(S_SQLFAIL);
		}

		unlink($delfile);
		unlink($delthumb);

		if (!STAFF_ONLY && !2CH_MODE && !$deleted) {
			if (!$dresto) $dresto = $dno;
			if (!isset($updated[$dresto])) {
				updatethread($dresto);
				$updated[$dresto] = 1;
			}
		}
	}

	if (!STAFF_ONLY)
		updatelog();
}

function checkpass($pass, $realpass, $automated) {
	global $validated;

	if ($automated) return 1;

	if ($validated) {
		if ($_REQUEST['token'] == $_SESSION['token'])
			return 1;
	}

	if (crypt($pass, $realpass) == $realpass)
		return 1;

	if (crypt($_COOKIE['pwdc'], $realpass) == $realpass)
		return 1;

	return 0;
}

function report($post, $reason) {
	if (!$reason)
		error(S_NOREASON);
	else
		$reason = cleanstring($reason);

	$delno = array();
	// im going to overhaul the shit out of this soon
	while ($item = each($_POST)){
		if ($item[1] == 'delete')
			array_push($delno, $item[0]);
	}

	$repcount = count($delno);
	if ($repcount > MAX_REPORTS)
		error(S_REPFLOOD);

	for ($i = 0; $i < $repcount; $i++) {
		$query = "SELECT no,sticky,resto FROM ".SQLLOG." WHERE no=%s";
		if (!$result = mysql_prepare($query, $delno[$i]))
			die(mysql_error());

		if (!$row = mysql_fetch_row($result))
			error(S_POSTGONE);

		if ($row[1])
			error(S_STICKY);

		$thread = (!$row[2]) ? $row[0] : $row[2];
		$link = BOARD_DIR.PHP_SELF3."&t=$thread#".$row[0];
		$no = BOARD_DIR.$delno[$i];

		$ip = $_SERVER['REMOTE_ADDR'];
		$query = "INSERT INTO ".SQLREP." VALUES(null,%s,%s,%s,%s)";
		$result = mysql_prepare($query, $ip, $link, $no, $reason);
		if (!$reason)
			die(mysql_error());
	}
}

// this is shit, im shit
// its my birthday someone kill me
function filter_post_ranges($posts, $ranges) {
	$selected = array();
	$total = count($posts);

	$ranges = explode(',' $ranges);
	foreach ($ranges as $range) {
		if (preg_match('/^([0-9]*)-([0-9]*)$/', $range)) {
			list ($start, $end) = explode('-', $range);
			if (!$start)
				$start = 1;
			else if ($start > $total)
				$start = $total;

			if (!$end || $end > $total) 
				$end = $total;

			if ($start > $end)
				list ($start, $end) = array($end, $start);

			$start--;
			for ($i = $start; $i < $end; $i++) {
				$posts[$i]['pos'] = $i + 1;
				$selected[] = $posts[$i];
			}
		}
		else if (preg_match('/^([0-9]+)$/', $range, $matches)) {
			$post = ($matches[0] > $total) ? $total : $matches[0];
			$i = $matches[0] - 1;
			$posts[$i]['pos'] = $matches[0];
			$selected[] = $posts[$i];
		}
		else if (preg_match('/^l([0-9]+)$/', $range, $matches)) {
			$selected[] = $posts[0];
			$start = $total - $matches[0] - 1;
			if ($start < 1) $start = 1;
			for ($i = $start; $i < $total; $i++) {
				$posts[$i]['pos'] = $i + 1;
				$selected[] = $posts[$i];
			}
		}
		else
			return $posts;
	}

	return $selected;
}

function read_thread() {
	$args = explode('/', $_SERVER['PATH_INFO']);
	if (!is_int($args[1]))
		error(S_UNUSUAL);

	updatethread($args[1], 0, $args[2]);
}

function update_subback($subs, $cache = 1) {
	if (!$subs) {
		$cache = 0;
		$query = "SELECT no,sub FROM ".SQLLOG." WHERE root>0 ORDER BY sticky DESC,root DESC";
		if (!$result = mysql_call($query))
			echo S_SQLFAIL;

		while ($row = mysql_fetch_row($result)) {
			$count = threadcount($row[0]) + 1;
			$subs[$row[0]] = $row[1];
			$subs[$row[0]]['count'] = $count;
		}
	}

	$dat = build_subback($subs);
	printpage($cache, $dat, 0, 'subback');
}

function valid($user, $pass, $token){
	global $validated;
	if ($user) {
		if (!login($user, $pass, $token))
			error(S_REJECT);
		else
			$validated = validate();
	}

	head($dat);
	echo $dat;
	if (!$validated) {
		$_SESSION['token'] = md5(uniqid(mt_rand().mt_rand(), true));
		$page = 'login';
		include MANAGER_TEMPLATE;
		die();
	}
}

function validate() {
	if (!isset($_SESSION['user_id']) || !trim($_SESSION['user_id']))
		return 0;

	if (!isset($_SESSION['token']) || !trim($_SESSION['token']))
		return 0;

	if (!isset($_SESSION['useragent']) || !trim($_SESSION['useragent']))
		return 0;

	if ($_SERVER['HTTP_USER_AGENT'] != $_SESSION['useragent'])
		return 0;

	$query = "SELECT level FROM ".SQLADMIN." WHERE no=%s";
	if (!$result = mysql_prepare($query, $_SESSION['user_id']))
		die(mysql_error());

	if (!$stafflevel = mysql_fetch_assoc($result))
		return 0;
	else
		return $stafflevel['level'];
}

function login($username, $pass, $token) {
	if (!isset($username) || !trim($username))
		error(S_REJECT);

	if (!isset($pass) || !trim($pass))
		error(S_REJECT);

	if (!isset($token) || !trim($token))
		error(S_REJECT);

	if ($token != $_SESSION['token'])
		error(S_CSRF);

	$query = "SELECT no,pass FROM ".SQLADMIN." WHERE name=%s";
	if (!$result = mysql_prepare($query, $username))
		die(mysql_error());

	if (!$staffrow = mysql_fetch_assoc($result))
		error(S_WRONGUSER);

	if (crypt($pass, $staffrow['pass']) != $staffrow['pass'])
		error(S_WRONGPASS);

	session_regenerate_id(true);
	$_SESSION['user_id'] = $staffrow['no'];
	$_SESSION['useragent'] = $_SERVER['HTTP_USER_AGENT'];
	$query = "UPDATE ".SQLADMIN." SET ip=%s WHERE no=%s";
	if (!$result = mysql_prepare($query, $_SERVER['REMOTE_ADDR'], $staffrow['no']))
		die(mysql_error());

	return 1;
}

function logout() {
	$_SESSION = array();
	$params = session_get_cookie_params();
	setcookie(
		session_name(), time() - 4000,
		$params['path'], $params['domain'],
		$params['secure'], $params['httponly']
	);
	session_destroy();
	header('Location: '.PHP_SELF.'?mode=admin');
	die();
}

function create_user($username, $pass, $level) {
	global $validated;

	if ($validated < 2)
		error(S_NOTADMIN);

	if ($username) {
		if ($_POST['token'] != $_SESSION['token'])
			error(S_CSRF);

		if ($level > 2 && $validated != 3)
			error(S_NOTOP);

		$pass = crypt($pass);
		$query = "INSERT INTO ".SQLADMIN." VALUES(null,%s,%s,'',%s)";
		if (!$result = mysql_prepare($query, $username, $pass, $level))
			die(mysql_error());
		
		$success = 1;
	}

	$page = 'createuser';
	include MANAGER_TEMPLATE;
	die();
}

function delete_user($id) {
	global $validated;

	if ($validated < 2)
		error(S_NOTADMIN);

	if ($id) {
		if ($_POST['token'] != $_SESSION['token'])
			error(S_CSRF);

		foreach ($id as $num) {
			$query = "SELECT level FROM ".SQLADMIN." WHERE no=%s";
			if (!$result = mysql_prepare($query, $num))
				die(mysql_error());

			if (!$row = mysql_fetch_row($result))
				error(S_NOUSER);

			if ($row[0] > 2 && $validated != 3)
				error(S_NOTOP);

			$query = "DELETE FROM ".SQLADMIN." WHERE no=%s";
			if (!$result = mysql_prepare($query, $num))
				die(mysql_error());
		}
		$success = 1;
	}

	$query = "SELECT no,name,level FROM ".SQLADMIN;
	if (!$result = mysql_call($query))
		echo S_SQLFAIL;

	$page = 'deleteuser';
	include MANAGER_TEMPLATE;
	die();
}

function change_password($oldpass, $newpass, $confirm) {
	if (isset($oldpass) && isset($newpass)) {
		if ($_POST['token'] != $_SESSION['token'])
			error(S_CSRF);

		if ($newpass != $confirm)
			error(S_NOMATCH);

		$query = "SELECT pass FROM ".SQLADMIN." WHERE no=%s";
		if (!$result = mysql_prepare($query, $_SESSION['user_id']))
			die(mysql_error());

		if (!$staffpass = mysql_fetch_assoc($result))
			error(S_NOUSER);
	
		if (crypt($oldpass, $staffpass['pass']) != $staffpass['pass'])
			error(S_WRONGPASS);

		$newpass = crypt($newpass);
		$query = "UPDATE ".SQLADMIN." SET pass=%s WHERE no=%s";
		if (!$result = mysql_prepare($query, $newpass, $_SESSION['user_id']))
			die(mysql_error());

		$success = 1;
	}

	$page = 'changepass';
	include MANAGER_TEMPLATE;
	die();
}

function change_level($user, $level) {
	global $validated;

	if ($validated < 2)
		error(S_NOTADMIN);

	if (isset($user) && isset($level)) {
		if (!$_POST['token'] != $_SESSION['token'])
			error(S_CSRF);

		if ($level != 1 && $level != 2 && $level != 3)
			error(S_UNUSUAL);

		$query = "SELECT level FROM ".SQLADMIN." WHERE no=%s";
		if (!$result = mysql_prepare($query, $user))
			die(mysql_error());

		if (!$row = mysql_fetch_row($result))
			error(S_NOUSER);

		if (($row[0] > 2 || $level > 2) && $validated != 3)
			error(S_NOTOP);

		$query = "UPDATE ".SQLADMIN." SET level=%s WHERE no=%s";
		if (!$result = mysql_prepare($query, $level, $user))
			die(mysql_error());

		$success = 1;
	}

	$query = "SELECT no,name FROM ".SQLADMIN."";
	if (!$result = mysql_call($query))
		echo S_SQLFAIL;

	$page = 'changelevel';
	include MANAGER_TEMPLATE;
	die();
}

function panel_mainpage() {
	global $validated;

	$page = 'mainpage';
	include MANAGER_TEMPLATE;
	die();
}

function is_banned() {
	$ip = (float)sprintf("%u", ip2long($_SERVER['REMOTE_ADDR']));
	$banned = false;
	$query = "SELECT reason,filed,expires FROM ".SQLBANS." WHERE startip <= %s AND endip >= %s LIMIT 1";
	if (!$result = mysql_prepare($query, $ip, $ip))
		die(mysql_error());

	if ($banstuff = mysql_fetch_row($result))
		$banned = $banstuff;

	return $banned;
}

function remove_expired_bans() {
	$time = time();
	if (!mysql_call("DELETE FROM ".SQLBANS." WHERE expires>0 AND expires < $time")) {
		echo S_SQLFAIL;

	if (mysql_affected_rows() > 0)
		updatehtaccess();
}

function ban($ip, $post, $reason, $bantype, $length, $increment, $after, $append) {
	global $validated;

	if (!$ip)
		error(S_BANWHAT);

	$query = "SELECT level FROM ".SQLADMIN." WHERE ip=%s";
	if (!$result = mysql_prepare($query, $ip))
		die(mysql_error());

	if ($row = mysql_fetch_row($result)) {
		if ($row[0] >= $validated)
			error(S_PERMS);
	}

	if (strpos($ip, '-') !== false) {
		$iprange = explode('-', $ip);
		list ($startip, $endip) = $range;
	}
	else if (strpos($ip, '*') !== false) {
		$startip = str_replace('*', 0, $ip);
		$endip = str_replace('*', 255, $ip);
	}
	else 
		$startip = $endip = $ip;

	if (!$reason)
		error(S_NEEDREASON);
	else
		$reason = nl2br($reason);

	$time = time();
	if ($bantype == 'permaban')
		$banend = 0;
	else if ($bantype == 'suspension')
		$banend = $time + ($length * $increment);

	$startip = (float)sprintf("%u", ip2long($startip));
	$endip = (float)sprintf("%u", ip2long($endip));

	$query = "INSERT INTO ".SQLBANS." VALUES(null,%s,%s,%s,%s,%s,%s,%s)";
	$result = mysql_prepare(
		$query, $ip, $startip, $endip, 
		$reason, $bantype, $time, $banend
	);
	if (!$result)
		die(mysql_error());
	
	updatehtaccess();

	if ($after == 'delpost') {
		$_POST[$post] = 'delete';
		usrdel($post);
	}
	else if ($after == 'append') {
		$append = "<br /><br />".$append;
		$query = "UPDATE ".SQLLOG." SET modnote=%s,root=root WHERE no=%s";
		if (!mysql_prepare($query, $append, $post))
			die(mysql_error());
	}
}

function delete_ban($id) {
	if ($_POST['token'] != $_SESSION['token'])
		error(S_CSRF);

	$query = "DELETE FROM ".SQLBANS." WHERE no=%s";
	if (!mysql_prepare($query, $id))
		die(mysql_error());

	updatehtaccess();
}

function updatehtaccess() {
	$htaccess = "<IfModule mod_rewrite.c>";
	$htaccess .= "\nRewriteEngine on";
	$htaccess .= "\nRewriteBase ".BOARD_DIR;
	if (!$result = mysql_call("SELECT ip,startip,endip FROM ".SQLBANS))
		echo S_SQLFAIL;

	$i = 0;
	$bans = mysql_num_rows($result);
	while ($iprow = mysql_fetch_row($result)) {
		$i++;
		$append = '';
		if ($i != $bans)
			$append = '[OR]';

		list ($ip, $startip, $endip) = $iprow;
		if (strpos($ip, '-') !== false) {
			for ($i = $startip; $i <= $endip; $i++) {
				$newip = long2ip($i);
				$newip = str_replace('.', '\.', $newip);
				$htaccess .= "\nRewriteCond %{REMOTE_ADDR} $newip$ $append";
			}
		}
		else {
			if (strpos($ip, '*') !== false)
				$ip = str_replace('.*', '', $ip);
			else
				$ip .= '$';

			$ip = str_replace('.', '\.', $ip);
			$htaccess .= "\nRewriteCond %{REMOTE_ADDR} $ip $append";
		}
	}
	if ($i) {
		$htaccess .= "\nRewriteCond %{REQUEST_URI} !^imgboard.php$";
		$htaccess .= "\nRewriteRule ^(.*)$ imgboard.php [R,L]";
	}
	$what = fopen(".htaccess", "w");
	fwrite($what, $htaccess);
	fclose($what);
}

function banpage() {
	$result = is_banned();
	if (!$result) {
		echo 'Youre not banned';
		die();
	}
	list ($reason, $time, $banend) = $result;
	if (!$banend) {
		$howlong = '&nbsp;permanently';
		$expireline = 'it will not expire';
	}
	else {
		$howlong = '';
		$expiredate = date("F j, Y", $banend);
		$expireline = "it expires on $expiredate";
	}
	$when = date("F j, Y", $time);

	include BANPAGE_TEMPLATE;
	die();
}

function sticky($thread) {
	$query = "SELECT resto,sticky FROM ".SQLLOG." WHERE no=%s";
	if (!$result = mysql_prepare($query, $thread))
		die(mysql_error());

	if (!$row = mysql_fetch_assoc($result))
		die(S_NOTHREADERR);

	if ($row['resto'])
		error(S_NOTATHREAD);
	else {
		$sticky = (!$row['sticky']) ? 1 : 0;
		$query = "UPDATE ".SQLLOG." SET sticky=$sticky,root=root WHERE no=%s";
		if (!$result = mysql_prepare($query, $thread))
			die(mysql_error());
	}

	updatethread($thread);
	updatelog();
}

function lock($thread) {
	$query = "SELECT resto,locked FROM ".SQLLOG." WHERE no=%s";
	if (!$result = mysql_prepare($query, $thread))
		die(mysql_error());

	if (!$row = mysql_fetch_assoc($result))
		die(S_NOTHREADERR);

	if ($row['resto'])
		error(S_NOTATHREAD);
	else {
		$lock = (!$row['locked']) ? 1 : 0;
		$query = "UPDATE ".SQLLOG." SET locked=$lock,root=root WHERE no=%s";
		if (!$result = mysql_prepare($query, $thread))
			die(mysql_error());
	}

	updatethread($thread);
	updatelog();
}

function delete_all($from, $arg) {
	global $validated;

	if ($from == 'new') {
		$timeframe = time() - 86400;
		if (!$result = mysql_call("SELECT no FROM ".SQLLOG." WHERE time>=".$timeframe))
			echo S_SQLFAIL;
	}
	else if ($from == 'ip') {
		$query = "SELECT no FROM ".SQLLOG." WHERE host=%s";
		if (!$result = mysql_prepare($query, $arg))
			die(mysql_error());

	}
	else {
		if ($validated < 3)
			error(S_NOTOP);

		if (!$result = mysql_call("SELECT no FROM ".SQLLOG." WHERE root>0"))
			echo S_SQLFAIL;
	}

	while ($row = mysql_fetch_row($result)) {
		$_POST[$row[0]] = 'delete';
	}

	usrdel(0, 0, 1);
}

function ban_all($org, $arg, $reason, $bantype, $length, $increment, $after, $append) {
	if ($org == 'new') {
		$timeframe = time() - 86400;
		if (!$result = mysql_call("SELECT DISTINCT no,host FROM ".SQLLOG." WHERE time>=".$timeframe))
			echo S_SQLFAIL;
	}
	else if ($org == 'threads') {
		$query = "SELECT DISTINCT no,host FROM ".SQLLOG." WHERE no=%s OR resto=%s";
		if (!$result = mysql_prepare($query, $arg, $arg))
			die(mysql_error());
	}
	else {
		if (!$result = mysql_call("SELECT DISTINCT no,host FROM ".SQLLOG))
			echo S_SQLFAIL;
	}

	while ($row = mysql_fetch_row($result)) {
		ban(	$row[1], $row[0], $reason, $bantype, 
			$length, $increment, $after, $append
		);
	}
}

// this is literally the worst piece of shit ever written
function manage($org, $page = 1, $arg) {
	$frontlimit = (40 * $page) - 40;
	$limit = "LIMIT $frontlimit, 40";
	$bindings = array();
		
	if ($org == 'all') {
		$query = "SELECT * FROM ".SQLLOG." ORDER BY no DESC $limit";
		$count = "SELECT count(*) FROM ".SQLLOG."";
	}
	else if ($org == 'threads') {
		if ($arg) {
			$bindings[] = $bindings[] = $arg;
			$query = "SELECT * FROM ".SQLLOG." WHERE no=%s OR resto=%s ORDER BY no DESC $limit";
			$count = "SELECT count(*) FROM ".SQLLOG." WHERE no=%s OR resto=%s";
		}
		else {
			$org = 'displaythreads';
			$query = "SELECT * FROM ".SQLLOG." WHERE root>0 ORDER BY root DESC $limit";
			$count = "SELECT count(*) FROM ".SQLLOG." WHERE root>0";
		}
	}
	else if ($org == 'ip') {
		$bindings[] = $arg;
		$query = "SELECT * FROM ".SQLLOG." WHERE host=%s ORDER BY no DESC $limit";
		$count = "SELECT count(*) FROM ".SQLLOG." WHERE host=%s ORDER BY no DESC $limit";
	}
	else {
		$timeframe = time() - 86400;
		$query = "SELECT * FROM ".SQLLOG." WHERE time>=$timeframe ORDER BY no DESC $limit";
		$count = "SELECT count(*) FROM ".SQLLOG." WHERE time>=$timeframe";
	}

	array_unshift($bindings, $count);
	$result = call_user_func_array('mysql_prepare', $bindings);

	if (!$result)
		die(mysql_error());

	$row = mysql_fetch_row($result);
	$posts = $row[0];
	$pages = $posts / 40;

	if ($pages < 1) 
		$pages = 1;
	else 
		floor($pages);

	array_shift($bindings);
	array_unshift($bindings, $query);
	$result = call_user_func_array('mysql_prepare', $bindings);

	if (!$result)
		die(mysql_error());

	include FUTABALIGHT_TEMPLATE;
	die();
}

function banform($org, $ip, $id, $banall) {
	$page = 'bans';
	include MANAGER_TEMPLATE;
	die();
}

function managebans() {
	if (!$result = mysql_call("SELECT no,ip,reason,filed,expires FROM ".SQLBANS))
		echo S_SQLFAIL;

	$page = 'bans';
	$showbans = 1;
	$org = 'banpage';

	include MANAGER_TEMPLATE;
	die();
}

function managereports($dismiss) {
	if ($dismiss) {
		if ($_POST['token'] != $_SESSION['token'])
			error(S_CSRF);

		foreach ($dismiss as $id) {
			$query = "DELETE FROM ".SQLREP." WHERE num=%s";
			if (!mysql_prepare($query, $id))
				die(mysql_error());
		}
		$success = 1;
	}

	if (!$result = mysql_call("SELECT * FROM ".SQLREP))
		die(S_SQLFAIL);

	$reportlist = array();
	$countlist = array();
	while ($row = mysql_fetch_assoc($result)) {
		$countlist[$row['num']]++;
		$reportlist[$row['num']][] = $row;
	}

	arsort($countlist, SORT_NUMERIC);

	$page = 'reports';
	include MANAGER_TEMPLATE;
	die();
}	

function updateall() {
	if (STAFF_ONLY)
		return;

	if (2CH_MODE) {
		updatelog();
		return;
	}
	if (!$result = mysql_call("SELECT no FROM ".SQLLOG." WHERE root>0"))
		echo S_SQLFAIL;

	while ($threadno = mysql_fetch_row($result)) {
		updatethread($threadno[0]);
	}
	updatelog();
}

function cleantempdir() {
	$handle = opendir(TMP_DIR);
	while (false !== ($entry = readdir($handle))) {
		$endtime = stat(TMP_DIR.$entry);
		$elapse = time() - $endtime['mtime'];
		if ($elapse > TMP_LIMIT)
			unlink(TMP_DIR.$entry);
	}
}

function create_ban_table() {
	$result = mysql_call("
		create table ".SQLBANS." (primary key(no),
		no 	int not null auto_increment,
		ip 	text,
		startip text,
		endip 	text,
		reason 	text,
		type	text,
		filed	int,
		expires	int)
	");

	if (!$result) die(mysql_error());
}

function create_admin_table() {
	$result = mysql_call("
		create table ".SQLADMIN." (primary key(no),
		no    int not null auto_increment,
		name  text,
		pass  text,
		ip    text,
		level int)
	");

	if (!$result) die(mysql_error());

	$pass = crypt(PANEL_PASS);
	$query = "INSERT INTO ".SQLADMIN." VALUES(null,%s,%s,%s,%s)";
	$result = mysql_prepare($query, DEFAULT_USER, $pass, '', 3);
	if (!$result)
		die(mysql_error());
}

function create_reports_table() {
	$result = mysql_call("
		CREATE TABLE ".SQLREP." (PRIMARY KEY(no),
		no     int not null auto_increment,
		ip     text,
		link   text,
		num    int,
		reason text)
	");
	if (!$result) die(mysql_error());
}

function create_post_table() {
	$result = mysql_call("
		create table ".SQLLOG." (primary key(no),
		no      int not null auto_increment,
		now     text,
		name    text,
		email   text,
		sub     text,
		com     text,
		host    text,
		pwd     text,
		ext     text,
		w       int,
		h       int,
		tw      int,
		th      int,
		tim     text,
		time    int,
		md5     text,
		upname  text,
		fsize   int,
		locked  int,
		sticky  int,
		root    timestamp,
		resto   int,
		modnote text)
	");
	if (!$result) die(mysql_error());
}

?>
