<?php

namespace Geisinger\ShibbolethSurveyAuth;

use ExternalModules\AbstractExternalModule;
use REDCap;

class ShibbolethSurveyAuth extends AbstractExternalModule
{
	private $defaultGrace = 15;
	public $defaultItem = "HTTP_REMOTE_USER";

	public function redcap_module_system_enable($version)
	{
		$salt = $this->getSystemSetting("salt");
		$pepper = $this->getSystemSetting("pepper");
		if (empty($salt))
			$this->setSystemSetting("salt",  base64_encode(random_bytes(32)));
		if (empty($pepper))
			$this->setSystemSetting("pepper", base64_encode(random_bytes(32)));
	}

	public function redcap_survey_page_top($project_id, $record, $instrument, $event, $group, $survey)
	{
		$auth = $_GET["auth"] ?? $_COOKIE["ShibbolethSurveyAuth"];
		$session = $_COOKIE["survey"]; // Session id used for surveys
		$item = $this->getSystemSetting("user-item");
		$user = $_SERVER[empty($item) ? $this->defaultItem : $item];
		$time = time();

		// If unauthenticated, kick to login
		if (empty($auth) || empty($user))
			$this->sendToAuthPage($survey);

		// Calc valid hashes
		$grace = intval($this->getSystemSetting("grace"));
		$grace = $grace == 0 ? $this->defaultGrace : $grace;
		for ($i = 0; $i < $grace; $i++)
			$validHashList[] = $this->makeHash($project_id, $session, $user, $time - (60 * $i));

		// Check if hash is invalid, kick to login
		if (!in_array($auth, $validHashList))
			$this->sendToAuthPage($survey);

		// Log a successful authentication
		REDCap::logEvent("Authenticated Survey", "User: $user", null, $record, $event, $project_id);

		// User is authenticated, check for action tag and build JS
		$js = [];
		$dd = REDCap::getDataDictionary("array", false, null, $instrument);
		foreach ($dd as $field => $props) {
			if (in_array($props["field_type"], ["text", "notes"]) && (strpos($props["field_annotation"], "@SSOUSER") !== false)) {
				$selector = "document.querySelector('" . ($props["field_type"] == "notes" ? "textarea" : "input") . "[name=$field]')";
				$js[] = "$selector.value = '$user';";
				$js[] = "$selector.dispatchEvent(new Event('change'));";
			}
		}

		// If action tag exists, pass down JS to fill in the field
		if (count($js) > 0) {
			$js = implode("\n", $js);
			echo "<script> document.addEventListener('DOMContentLoaded', () => {
				$js
			}); </script>";
		}
	}

	public function makeHash($project_id, $session, $user, $time)
	{
		$salt = $this->getSystemSetting("salt");
		$pepper = $this->getSystemSetting("pepper");
		$time = round($time / 60) * 60; // rounded to nearest min
		return hash("sha256", "$salt$project_id$session$user$time$pepper");
	}

	private function sendToAuthPage($survey)
	{
		$url = $this->getUrl("login.php", true); // No auth url
		header("Location: $url&s=$survey");
		$this->exitAfterHook();
	}
}
