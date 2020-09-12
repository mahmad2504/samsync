<?php
require 'vendor/autoload.php';
require 'conf.txt';
require 'credentials.txt';
use \MongoDB\Client;
use \MongoDB\BSON\UTCDateTime;
$url='https://svm.cert.siemens.com/portal/api/v1';
//phpinfo();


function getContentBycURL($strURL)
{
	//echo $strURL."\n";
	$ch = curl_init();
	$proxyserver='http://cyp-fsrprx.net.plm.eds.com:2020';
	curl_setopt($ch, CURLOPT_HEADER, 0);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1); // Return data inplace of echoing on screen
	curl_setopt($ch, CURLOPT_URL, $strURL);
	curl_setopt($ch, CURLOPT_VERBOSE, '0');
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, '2');
	//curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, '1');
	curl_setopt($ch, CURLOPT_SSLCERT, getcwd() . "/Z003UJ3F_cert.pem");
	curl_setopt($ch, CURLOPT_SSLKEY, getcwd() . "/Z003UJ3F_key.pem");
	//New commands
	//curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
	curl_setopt($ch, CURLOPT_PROXY, 'cyp-fsrprx.net.plm.eds.com' );
	curl_setopt($ch, CURLOPT_PROXYPORT, '2020');
	curl_setopt($ch, CURLOPT_PROXYUSERPWD, "$GLOBALS[username]:$GLOBALS[password]");
    curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
	curl_setopt($ch, CURLOPT_PROXYAUTH, CURLAUTH_NTLM);
	//curl_setopt($ch, CURLOPT_KEEP_SENDING_ON_ERROR, TRUE);
	
	curl_setopt($ch, CURLOPT_CAINFO, getcwd() . "/siemens_root_ca_v3.0_2016.pem");
	curl_setopt($ch, CURLOPT_CAPATH, getcwd() . "/siemens_root_ca_v3.0_2016.pem");
	//curl_setopt($ch, CURLOPT_CAINFO, "/etc/ssl/certs/ca-certificates.crt");
	$rsData = curl_exec($ch);
	$error = curl_error($ch);
	if($error != null)
	{
		echo $error;
		return [];
	}
	$data = json_decode($rsData);
	
	if(isset($data->errors))
	{
		json_encode($data->errors);
		return [];
	}
	curl_close($ch);
	return $data;
}
$mongoClient=new Client("mongodb://127.0.0.1");
//$mongoClient=new Client("mongodb://10.103.17.174");

$db = $mongoClient->cveportal;

$db->cpe2->drop();
//$monitoring_list_ids = ['7947066E','24A891CF'] ;//['7947066E','6EA3903D'];
	


$monitoring_lists = [];
foreach($monitoring_list_ids as $monitoring_list_id)
{
	echo "Processing monitoring list [id=".$monitoring_list_id."]\r\n";
	echo "Fetching component list ";
	$components =  getContentBycURL($url.'/common/monitoring_lists/'.$monitoring_list_id.'/components');
	echo "\r\n" . count($components)." Found\r\n";
	echo "Fetching list notifications ";
	$notifications = getContentBycURL($url.'/common/monitoring_lists/'.$monitoring_list_id.'/notifications');
	echo "\r\n" . count($notifications)." Found\r\n";
	$count = count($components);
	$i=0;
	$monitoring_list = new StdClass();
	$monitoring_list->id = $monitoring_list_id;
	$monitoring_list->components = [];
	foreach($components as $componentid)
	{
		$monitoring_list->components[$componentid] = $componentid;
		$query =['id'=>$componentid];
		$projection = ['projection'=>['_id'=>0]];
		$component = $db->cpe2->findOne($query,$projection);
		$i++;
		if($component != null)
		{
			echo $i."/".$count." Scanning  ".$component->component_name."[".$component->version."] notifications   ".$component->notifications_count." Found\r\n";
			continue;
		}
	
		$query =['id'=>$componentid];
		$projection = ['projection'=>['_id'=>0]];
		$component = $db->components->findOne($query,$projection);
		if($component == null)
		{
			echo "Fetching Component [id=".$componentid."] details from svm"."\r\n";
			$component = getContentBycURL($url.'/public/components/'.$componentid);
			$component->id = $componentid;
			$db->components->updateOne($query,['$set'=>$component],['upsert'=>true]);
		}
		echo $i."/".$count." Scanning  ".$component->component_name."[".$component->version."] notifications";
		$component->notifications =  getContentBycURL($url.'/public/components/'.$componentid.'/notifications');
		$component->_notifications = [];
		$component->notifications_count = count($component->notifications);
		echo "    ".count($component->notifications)." Found\r\n"; 
		foreach($component->notifications as $notification)
		{
			$query =['id'=>$notification->id];
			$projection = ['projection'=>['_id'=>0]];
			$n = $db->notifications->findOne($query,$projection);
			if($n == null)
			{
				echo "Fetching Notification [id=".$notification->id."] data"."\r\n";
				$notification->data = getContentBycURL($url.'/public/notifications/'.$notification->id);
				$db->notifications->updateOne($query,['$set'=>$notification],['upsert'=>true]);
			}
			else 
			{
				if($notification->last_update!=$n->last_update)
				{
					echo "Fetching Notification ".$notification->id." details from svm"."\r\n";
					$notification->data = getContentBycURL($url.'/public/notifications/'.$notification->id);
					$db->notifications->updateOne($query,['$set'=>$notification],['upsert'=>true]);
				}
				else
					$notification = $n;
			}
			$component->_notifications[] = $notification;
		}
		$component->notifications = $component->_notifications;
		unset($component->_notifications);
		
		$component->cve = [];
		
		foreach($component->notifications as $notification)
		{
			if(isset($notification->data->cve_references))
			{
				foreach($notification->data->cve_references as $cve)
				{
					$cve = 'CVE-'.$cve->year."-".$cve->number;
					$component->cve[$cve] = $cve;
				}
			}
		}
		$component->cve = array_values($component->cve);
		unset($component->notifications);
		$component->valid = 1;
		$query =['id'=>$componentid];
		$db->cpe2->updateOne($query,['$set'=>$component],['upsert'=>true]);
	}
	$query =['id'=>$monitoring_list->id];
	if(count($monitoring_list->components) > 0)
	{
		$components = $monitoring_list->components;
		$monitoring_list->components = array_values($monitoring_list->components);
		$db->monitoring_lists->updateOne($query,['$set'=>$monitoring_list],['upsert'=>true]);
		$monitoring_list->components = $components;
	}
	$monitoring_lists[$monitoring_list->id] = $monitoring_list;
}
foreach($sublists as $id=>$sublist)
{
	if(!isset($monitoring_lists[$id]))
	{
		$monitoring_list = new StdClass();
		$monitoring_list->id = $id;
		$monitoring_list->components = [];
		$monitoring_lists[$id] = $monitoring_list;
	}
	$monitoring_list = $monitoring_lists[$id];
		
	foreach($sublist as $sublist_id)
	{
		if(isset($monitoring_lists[$sublist_id]))
		{
			$sublist = $monitoring_lists[$sublist_id];
			foreach($sublist->components as $comp_id)
			{
				$monitoring_list->components[$comp_id] = $comp_id;
			}
		}
		else 
		{
			echo "ERROR :: monitoring list  ".$sublist_id." is not included in monitorin list\n";
		}
	}
	if(count($monitoring_list->components) > 0)
	{
		$components = $monitoring_list->components;
		$monitoring_list->components = array_values($monitoring_list->components);
		$query =['id'=>$id];
		$db->monitoring_lists->updateOne($query,['$set'=>$monitoring_list],['upsert'=>true]);
		$monitoring_list->components = $components;
	}
	//$monitoring_lists[$id]->
}

$db->cpe->drop();
$cpe2 = $db->cpe2->findOne([]);
if($cpe2 != null)
{
	$mongoClient->admin->command(['renameCollection'=>'cveportal.cpe2','to'=>'cveportal.cpe']);
}