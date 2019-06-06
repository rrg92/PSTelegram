param(
	$RecreateStorage = $false
)
#Módulo para o powershell!
$ErrorActionPreference= "Stop";

# GLOBALS

	#Global useful vars...
	$PSTelegramBot_ModuleRoot 	= (Split-Path -Parent $MyInvocation.MyCommand.Definition );
	$DirSep					= [IO.Path]::DirectorySeparatorChar.ToString()

	#This will contains the storage!
	if(!$Global:PSTelegramBot_Storage -or $RecreateStorage){
		$Global:PSTelegramBot_Storage=@{
			TOKENS 			=  @{
				LIST 		= @()
				DEFAULT		= $null
			}
			DEFA	= $null
		};
	}

# AUXILIARY	
	Function PSTelegramBot_CheckAssembly {
		param($Name)
		
		if($Global:PowerZabbix_Loaded){
			return $true;
		}
		
		if( [appdomain]::currentdomain.getassemblies() | ? {$_ -match $Name}){
			$Global:PowerZabbix_Loaded = $true
			return $true;
		} else {
			return $false
		}
	}
	
	## EXCEPTIONS HANDLING!
	#This is a function to format exceptions.
	Function PSTelegramBot_FormatExceptions {
		param($e,$BaseDir = "", $prefix = 'ERR')
		
		$msgTemplate 	= "$($prefix)_{0}[{6}]: {1}[{2}.{3}] >> {4} << --> {5}"
		$msgException	= @()
		
		if($e.IsExceptionContainer){
			$AllExceptions = $e.ExceptionList
		} else {
			$AllExceptions = $e;
		}
		
		
		$AllExceptions | %{
			if($_ -is [System.Exception]){
				$ex = $_;
			} else {
				$ex = $_.Exception;
			}
			
			
			if($_.InvocationInfo){
				$InvocInfo = $_.InvocationInfo
			}
					
			$num = 1;
			$BaseEx = $ex.GetBaseException();
			while($ex) {
				if($InvocInfo)
				{
					$numLinha 	= $InvocInfo.ScriptLineNumber
					$offset 	= $InvocInfo.OffsetInLine
					$linha		= $InvocInfo.Line.trim()
					$ScriptName = $InvocInfo.ScriptName.replace($BaseDir,'')
				} else {
					$numLinha 	= '?'
					$offset 	= '?'
					$linha		= '?'
					$ScriptName = '?'
				}
				
				$msg = $ex.Message
				$msgException += $msgTemplate -f $num,$ScriptName,$numLinha,$offset,$linha,$msg,$ex.getType().FullName
				$num++;
				
				$LastEx		= $ex;
				$ex 		= $ex.InnerException
				$InvocInfo 	= $ex.ErrorRecord.InvocationInfo;
			}
			
			if(!$LastEx.Equals($BaseEx)){
				$ex = $BaseEx;
				$InvocInfo = $ex.InvocationInfo;
				if($InvocInfo){
					$numLinha 	= $InvocInfo.ScriptLineNumber
					$offset 	= $InvocInfo.OffsetInLine
					$linha		= $InvocInfo.Line.trim()
				}
				
				$msgException += $msgTemplate -f $num,$linha,$linhaOffset,$code,$msg
			}
		}
		
		return $msgException -join "`r`n"
	}

	#PSCmdBot exceptions object!
	Function PSTelegramBot_GetNewException {
		param(
			$ID
			,$Msg = $null
			, $Inner = $null
			,[switch]$FatalException = $false
		)

		$ExceptionMessage = "$ID";
		
		if($Msg){
			$ExceptionMessage += ':'+$Msg;
		}
		
		
		if($Inner.Exception){
			$ErrorRecord = $Inner;
			$Inner = $Inner.Exception;
			if(!$Inner.ErrorRecord){
				$Inner | Add-Member -type Noteproperty -Name ErrorRecord -Value $ErrorRecord;
			}
		}
		
		$Ex = New-Object Exception($ExceptionMessage, $Inner);
		$Ex | Add-Member -Type Noteproperty -Name FatalException -Value $FatalException;
		return $Ex;
	}

	#Creates a new exception object that with have mulitple exceptions!
	Function PSTelegramBot_NewExceptionContainer {
		param($Exceptions = @())
		
		if(!$Exceptions){
			$Exceptions= @();
		}
		
		$Ex = New-Object Exception('EXCEPTION_CONTAINER', $null);
		$Ex | Add-Member -Type Noteproperty -Name ExceptionList -Value $Exceptions;
		$Ex | Add-Member -Type Noteproperty -Name IsExceptionContainer -Value $true;
		return $Ex;
	}

	Function PSTelegramBot_LoadJsonEngine {

		$Engine = "System.Web.Extensions"

		if(!(PSTelegramBot_CheckAssembly $Engine)){
			try {
				Add-Type -Assembly  $Engine
				$Global:PowerZabbix_Loaded = $true;
			} catch {
				throw "ERROR_LOADIING_WEB_EXTENSIONS: $_";
			}
		}

	}

	#Troca caracteres não-unicode por um \u + codigo!
	#Solucao adapatada da resposta do Douglas em: http://stackoverflow.com/a/25349901/4100116
	Function PSTelegramBot_EscapeNonUnicodeJson {
		param([string]$Json)
		
		$Replacer = {
			param($m)
			
			return [string]::format('\u{0:x4}', [int]$m.Value[0] )
		}
		
		$RegEx = [regex]'[^\x00-\x7F]';
		write-verbose "$($MyInvocation.InvocationName):  Original Json: $Json";
		$ReplacedJSon = $RegEx.replace( $Json, $Replacer)
		write-verbose "$($MyInvocation.InvocationName):  NonUnicode Json: $ReplacedJson";
		return $ReplacedJSon;
	}

	#Converts objets to JSON and vice versa,
	Function PSTelegramBot_ConvertToJson($o) {
		
		if(Get-Command ConvertTo-Json -EA "SilentlyContinue"){
			return PSTelegramBot_EscapeNonUnicodeJson(ConvertTo-Json -Depth 10 $o -Compress);
		} else {
			write-verbose "Using Serialize...";
			PSTelegramBot_LoadJsonEngine
			$jo=new-object system.web.script.serialization.javascriptSerializer
			$jo.maxJsonLength=[int32]::maxvalue;
			return PSTelegramBot_EscapeNonUnicodeJson ($jo.Serialize($o))
		}
	}

	Function PSTelegramBot_ConvertFromJson([string]$json) {
	
		if(Get-Command ConvertFrom-Json  -EA "SilentlyContinue"){
			ConvertFrom-Json $json;
		} else {
			PSTelegramBot_LoadJsonEngine
			$jo=new-object system.web.script.serialization.javascriptSerializer
			$jo.maxJsonLength=[int32]::maxvalue;
			return $jo.DeserializeObject($json);
		}
		

	}

	#Get a emoji string
	Function PsTelegramBot_GetEmojiString {
		param(
			$emoji
			,$count = 1
		)
		
		if($emoji -is [int]){
			return [string]( [char]::ConvertFromUtf32($emoji) ) * $count;
		}
		
	}
	
	#Converts a hashtable into a textual representation strings. Each key is returned a string like KEYNAME = VALUE
	#If the key a another hash, then it will be represented as "PARENTKEYNAME" + $SEPARATOR + "KEYNAME" = VALUE, and so on.
	Function PSTelegramBot_Hash2String {
		param($Hash, $Separator='.', $ParentKey=$null, $KeyList = $null, $SensitiveList = @())

		$Results = @();

		$Hash.GetEnumerator() | %{
			$KeyName	= $_.Key;
			$Value 		= $_.Value;
			$Rep		= "";

			if($ParentKey){
				$FullName = $ParentKey+$Separator+$KeyName
			} else {
				$FullName = $KeyName;
			}


			if($Value -is [hashtable]){
				$Rep =  PSTelegramBot_Hash2String -Hash $Value -Separator $Separator -ParentKey $FullName -KeyList $KeyList -SensitiveList $SensitiveList
			} else {
				if($KeyList){
					if(-not ($KeyList|?{ $FullName -like $_ -or $FullName+$Separator -like $_ }) ){
						return;
					}
				}

				$ValuePart = ' = '+ $Value
				if($SensitiveList){
					if(($SensitiveList|?{ $FullName -like $_ -or $FullName+$Separator -like $_ }) ){
						$ValuePart = ' = ' + '*' * 3;
					}
				}

				$Rep += $FullName + $ValuePart;
			}
				
			if($Rep){
				$Results += $Rep;
			}
		}

		return $Results;
	}
	
	#Convert a PsCustomOject to hashtable!!!
	Function PSTelegramBot_Object2HashString {
		param($Objects, [switch]$Expand = $false, [switch]$PureHashTables = $false, $MaxDepths = 100, $CurrDepth = 0, $Processed = @(), $ExcludeProp = @())

		$ALLObjects = @()
		
		
		if($CurrDepth -gt $MaxDepths){
			return "MAX_DEPTHS_REACHED";
		}
		
		foreach($object in $Objects){
			$PropsString = @()
			
			if($Processed | ? { $_.Equals($object) }){
				return "***";
			}
			
			$Processed += $Object;
			
			$IsPrimitive = $false;
			
			if($object){
				$type = $object.getType();
				
				if($type.FullName -like "*[[][]]"){
					
					if($Expand){
						#If all elements of array are primitives, then represent the array as string!
						$IsPrimitiveArray = $true;
						$i = $object.count;
					
						while($i--){
							if($object[$i] -ne $null){
									$PosType = $object[$i].GetType();
									if(-not ($PosType.IsPrimitive -or [decimal],[string],[datetime] -contains $PosType) ){
										$IsPrimitiveArray  = $false;
										break;
									}
							}
						}


						if($IsPrimitiveArray){
							$AllObjects += $object -Join ",";
							continue;
						}

					}
				
					$ALLObjects += "$($type.FullName):$($object.length)";
					continue;
				}
				
				if($Type.IsPrimitive -or [decimal],[string],[datetime] -contains $type ){
					$IsPrimitive = $true;
				}
				
				if($IsPrimitive){
					$ALLObjects += $object.toString();
					continue;
				}

				
			
			}
			

			#if users wants expand and treat hashtable as a object, then convert it to a property of a object...
			if($object -is [hashtable] -and $Expand -and !$PureHashTables){
				if($object.count){
					$object = (New-Object PSObject -Prop $Object);
				} else {
					$object = (New-Object PSObject);
				}
				
				$Processed += $Object;
			}
			
			foreach($Prop in $Object.psobject.properties) { 
				
				if($ExcludeProp -Contains $Prop.Name){
					continue;
				}
				
				$PropValue = $Prop.Value;
				
				if( ($PropValue -is [psobject] -or ($PropValue -is [hashtable] -and !$PureHashTables)) -and $Expand){
					
					
					if($Processed | ? { $_.Equals($PropValue) }){
						return "***";
					}
					
					$Params = @{Object=$PropValue;Expand=$Expand;PureHashTables=$PureHashTables;CurrDepth=$CurrDepth+1;MaxDepths=$MaxDepths; Processed = $Processed}
					$PropValue  = PSTelegramBot_Object2HashString @Params;
				} else {
					if($PropValue){
						$type = $PropValue.getType();
						
						if($type.FullName -like "*[[][]]"){
							if($Expand){
								#If all elements of array are primitives, then represent the array as string!
								$IsPrimitiveArray = $true;
								$i = $PropValue.count;
							
								while($i--){
									if($PropValue[$i] -ne $null){
											$PosType = $PropValue[$i].GetType();
											if(-not ($PosType.IsPrimitive -or [decimal],[string],[datetime] -contains $PosType) ){
												$IsPrimitiveArray  = $false;
												break;
											}
									}
								}
							}

							if($IsPrimitiveArray){
								$PropValue = $PropValue -Join ","
							} else {
								$PropValue = "$($type.FullName):$($PropValue.length)";
							}
						} else {
							$PropValue = $PropValue.toString()
						}
						
					}
				}
				
				$PropsString	 += "$($Prop.Name)=$($PropValue)";
			}
			
			$ALLObjects += "@{"+($PropsString -join ";")+"}"
		}
		


		return ($ALLObjects -join "`r`n");
	}


	#Convert a datetime object to a unix time representation.
	Function PSTelegramBot_Datetime2Unix {
		param([datetime]$Datetime)
		
		return $Datetime.toUniversalTime().Subtract([datetime]'1970-01-01').totalSeconds;
	}

	#Converts a unixtime representation to a datetime in local time.
	Function PSTelegramBot_UnixTime2LocalTime {
		param([uint32]$unixts)
		
		return ([datetime]'1970-01-01').toUniversalTime().addSeconds($unixts).toLocalTime();
	}
	
	#Appends a root directory to a url if it is relatives
	Function PSTelegramBot_MakeAbsolutePath {
		param($Path, $Root)
		
		#TODO!
		return $Path;
	}
	
	#Make calls to a zabbix server url api.
	Function PSTelegramBot_CallTelegramURL([object]$data = $null,$url = $null,$method = "POST", $contentType = "application/json"){
		$ErrorActionPreference="Stop";
		
		write-verbose "$($MyInvocation.InvocationName):  URL param is: $Url";
		
		
		try {
			if(!$data){
				$data = "";
			}
		
			if($data -is [hashtable]){
				write-verbose "Converting input object to json string..."
				$data = PSTelegramBot_ConvertToJson $data; 
			}
			
			write-verbose "$($MyInvocation.InvocationName):  json that will be send is: $data"
			
			write-verbose "Usando URL: $URL"
		
			write-verbose "$($MyInvocation.InvocationName):  Creating WebRequest method... Url: $url. Method: $Method ContentType: $ContentType";
			$Web = [System.Net.WebRequest]::Create($url);
			$Web.Method = $method;
			$Web.ContentType = $contentType
			
			#Determina a quantidade de bytes...
			[Byte[]]$bytes = [byte[]][char[]]$data;
			
			#Escrevendo os dados
			$Web.ContentLength = $bytes.Length;
			write-verbose "$($MyInvocation.InvocationName):  Bytes lengths: $($Web.ContentLength)"
			
			
			write-verbose "$($MyInvocation.InvocationName):  Getting request stream...."
			$RequestStream = $Web.GetRequestStream();
			
			
			try {
				write-verbose "$($MyInvocation.InvocationName):  Writing bytes to the request stream...";
				$RequestStream.Write($bytes, 0, $bytes.length);
			} finally {
				write-verbose "$($MyInvocation.InvocationName):  Disposing the request stream!"
				$RequestStream.Dispose() #This must be called after writing!
			}
			
			
			
			write-verbose "$($MyInvocation.InvocationName):  Making http request... Waiting for the response..."
			$HttpResp = $Web.GetResponse();
			
			
			
			$responseString  = $null;
			
			if($HttpResp){
				write-verbose "$($MyInvocation.InvocationName):  charset: $($HttpResp.CharacterSet) encoding: $($HttpResp.ContentEncoding). ContentType: $($HttpResp.ContentType)"
				write-verbose "$($MyInvocation.InvocationName):  Getting response stream..."
				$ResponseStream  = $HttpResp.GetResponseStream();
				
				write-verbose "$($MyInvocation.InvocationName):  Response stream size: $($ResponseStream.Length) bytes"
				
				$IO = New-Object System.IO.StreamReader($ResponseStream);
				
				write-verbose "$($MyInvocation.InvocationName):  Reading response stream...."
				$responseString = $IO.ReadToEnd();
				
				write-verbose "$($MyInvocation.InvocationName):  response json is: $responseString"
			}
			
			
			write-verbose "$($MyInvocation.InvocationName):  Response String size: $($responseString.length) characters! "
			return $responseString;
		} catch {
			throw "ERROR_CALLING_TELEGRAM_URL: $_";
		} finally {
			if($IO){
				$IO.close()
			}
			
			if($ResponseStream){
				$ResponseStream.Close()
			}
			
			<#
			if($HttpResp){
				write-host "Finazling http request stream..."
				$HttpResp.finalize()
			}
			#>

		
			if($RequestStream){
				write-verbose "Finazling request stream..."
				$RequestStream.Close()
			}
		}
	}


	#Handle the zabbix server answers.
	#If the repsonse represents a error, a exception will be thrown. Otherwise, a object containing the response will be returned.
	Function PSTelegramBot_TranslateResponseJson {
		param($Response)
		
		#Converts the response to a object.
		$ResponseO = PSTelegramBot_ConvertFromJson $Response;
		
		#Check outputs
		if($ResponseO.ok -eq $false){
			$ResponseError = $ResponseO;
			$MessageException = "[$($ResponseError.error_code)]: $($ResponseError.description)";
			$Exception = New-Object System.Exception($MessageException)
			$Exception.Source = "TelegramAPI"
			throw $Exception;
			return;
		}
		
		
		#If not error, then return response result.
		return $ResponseO.result;
	}


	#Convert a datetime object to a unix time representation.
	Function PSTelegramBot_Datetime2Unix {
		param([datetime]$Datetime)
		
		return $Datetime.toUniversalTime().Subtract([datetime]'1970-01-01').totalSeconds;
	}

	#Converts a unixtime representation to a datetime in local time.
	Function PSTelegramBot_UnixTime2LocalTime {
		param([uint32]$unixts)
		
		return ([datetime]'1970-01-01').toUniversalTime().addSeconds($unixts).toLocalTime();
	}
	
	Function Set-DefaultToken {
		param($token)
		
		if(!$token){
			throw "PSTelegramBot_SETDEFAULTTOKEN_INVALID"
		}
		
		#Adds if not exists!
		Add-BotToken $token;
		
		$Global:PSTelegramBot_Storage.TOKENS.DEFAULT = $token;
	}
	
	Function Get-BotToken {
		[CmdLetBinding()]
		param($token)
		
		if($token){
			return $token;
		} else {
			$TokensStor = $Global:PSTelegramBot_Storage.TOKENS;
			
			if($TokensStor.LIST.count -eq 1){
				write-verbose "$($MyInvocation.InvocationName): Returning the unique token on list!"
				return $TokensStor.LIST[0];
			} else {
				return $TokenStor.DEFAULT;
			}
			
		}
		
		
	}
	
	Function Add-BotToken {
		param($token, [switch]$Default = $false)
		
		$TokensStor = $Global:PSTelegramBot_Storage.TOKENS;
		
		if(  $TokensStor.LIST -Contains $token){
			write-verbose "$($MyInvocation.InvocationName): Token already added!"
		} else {
			$TokensStor.LIST += $token;
		}
		
		if($Default){
			write-verbose "$($MyInvocation.InvocationName): Setting default token!"
			Set-DefaultToken $Token;
		}
	}
	

	#Copies bytes from a stream to another!
	Function PSTelegramBot_CopyToStream {
		param($From,$To)
		
		[Byte[]]$Buffer = New-Object Byte[](4096);
		$BytesRead = 0;
		while( ($BytesRead = $From.read($Buffer, 0,$Buffer.length)) -gt 0  ){
			$To.Write($buffer, 0, $BytesRead);
		}
	}

	#Converts a hashtable to a URLENCODED format to be send over HTTP requests.
	Function PSTelegramBot_BuildURLEncoded {
		param($DATA)
		
		$FinalString = @();
		$DATA.GetEnumerator() | %{
			$FinalString += "$($_.Key)=$($_.Value)";
		}

		Return ($FinalString -Join "&");
	}

	#Makes a POST HTTP call and return cmdlet with the results.
	#This will return a object containing following:
	#	raw 		- The raw bytes of response content.
	#	html		- The html respponse, if contentType is text/html
	#	httpResponse - The original http response object!
	#	session	- The session data, to be used as the parameter "session" to simulate sessions!
	Function PSTelegramBot_InvokeHttp {
		[CmdLetBinding()]
		param($URL, [hashtable]$data = @{}, $Session = $null, $method = 'POST', [switch]$AllowRedirect = $false)
		
		
		$Result = New-Object PsObject @{
			raw = $null
			html = $null
			httpResponse = $null
			session = @{cookies=$null}
		}
		
		$CookieContainer = New-Object Net.CookieContainer;
		
		if($Session){
			write-verbose "$($MyInvocation.InvocationName): Session was informed. Importing cookies!"
			$Session.Cookies | ?{$_} | %{
					write-verbose "$($MyInvocation.InvocationName): Cookie $($_.Name) imported!"
					$CookieContainer.add($_);
			}
		}
		
		try {
			$HttpRequest 					= [Net.WebRequest]::Create($URL);
			$HttpRequest.CookieContainer 	= $CookieContainer;
			$HttpRequest.Method 			= $method;
			$HttpRequest.AllowAutoRedirect 	= $AllowRedirect
			
			if($HttpRequest.method -eq 'POST'){
				write-verbose "$($MyInvocation.InvocationName): Setiing up the POST headers!"
				$PostData 	= PSTelegramBot_BuildURLEncoded $data
				write-verbose "$($MyInvocation.InvocationName): Post data encoded is: $PostData"
				$PostBytes 	= [System.Text.Encoding]::UTF8.GetBytes($PostData)
				$HttpRequest.ContentType = 'application/x-www-form-urlencoded';
				$HttpRequest.ContentLength 	= $PostBytes.length;
				write-verbose "$($MyInvocation.InvocationName): Post data length is: $($PostBytes.Length)"
				
				write-verbose "$($MyInvocation.InvocationName): getting request stream to write post data..."
				$RequestStream					= $HttpRequest.GetRequestStream();
				try {
					write-verbose "$($MyInvocation.InvocationName): writing the post data to request stream..."
					$RequestStream.Write($PostBytes, 0, $PostBytes.Length);
				} finally {
					write-verbose "$($MyInvocation.InvocationName): disposing the request stream..."
					$RequestStream.Dispose();
				}
			}
			
			write-verbose "$($MyInvocation.InvocationName): Calling the page..."
			$HttpResponse = $HttpRequest.getResponse();
			
			if($HttpResponse){
				write-verbose "$($MyInvocation.InvocationName): Http response received. $($HttpResponse.ContentLength) bytes of $($HttpResponse.ContentType)"
				$Result.httpResponse = $HttpResponse;
				
				if($HttpResponse.Cookies){
					write-verbose "$($MyInvocation.InvocationName): Generating response session!";
					$HttpResponse.Cookies | %{
						write-verbose "$($MyInvocation.InvocationName): Updating path of cookie $($_.Name)";
						$_.Path = '/';
					}
					
					$Result.session = @{cookies=$HttpResponse.Cookies};
				}
				
				
				write-verbose "$($MyInvocation.InvocationName): Getting response stream and read it..."
				$ResponseStream = $HttpResponse.GetResponseStream();
				
				write-verbose "$($MyInvocation.InvocationName): Creating memory stream and storing bytes...";
				$MemoryStream = New-Object IO.MemoryStream;
				PSTelegramBot_CopyToStream -From $ResponseStream -To $MemoryStream
				$ResponseStream.Dispose();
				$ResponseStream = $null;


				#If content type is text/html, then parse it!
				if($HttpResponse.contentType -like 'text/html;*'){
					write-verbose "$($MyInvocation.InvocationName): Creating streamreader to parse html response..."
					$MemoryStream.Position = 0;
					$StreamReader = New-Object System.IO.StreamReader($MemoryStream);
					write-verbose "$($MyInvocation.InvocationName): Reading the response stream!"
					$ResponseContent =  $StreamReader.ReadToEnd();
					write-verbose "$($MyInvocation.InvocationName): Using HAP to load HTML..."
					$HAPHtml = New-Object HtmlAgilityPack.HtmlDocument
					$HAPHtml.LoadHtml($ResponseContent);
					$Result.html = $HAPHtml;
				}
				
				write-verbose "$($MyInvocation.InvocationName): Copying bytes of result to raw content!";
				$MemoryStream.Position = 0;
				$Result.raw = $MemoryStream.toArray();
				$MemoryStream.Dispose();
				$MemoryStream = $null;
			}
			
			return $Result;
		} catch {
			throw "INVOKE_HTTP_ERROR: $_"
		} finnaly {
			if($MemoryStream){
				$MemoryStream.Dispose();
			}
			
			if($StreamReader){
				$StreamReader.Dispose();
			}
			
			
			if($ResponseStream){
				$ResponseStream.close();
			}
		
			if($HttpResponse){
				$HttpResponse.close();
			}
			

		}
		
	}
	
	
	
# TELEGRAM API
	## All methods parameters wil match name on API. Extensions will be flagged in comments.
	## Only parameters that exist on api documentation cannot needs comments.
	## All Methods must receive the $token with the token!
	## If api call returns error, the methods will trow it. The exception contains same errors returned by api when error.
	## https://core.telegram.org/bots/api


	# Implementation of getUpdates
	# https://core.telegram.org/bots/api#getupdates
	function Get-TelegramUpdates {
		[CmdLetBinding()]
		param(
			[string]$token
			,[int]$offset	= $null
			,[int]$limit 	= $null
			,[int]$timeout 	= $null 
			,[string[]]$allowed_updates = $null
		)
		
		$token = Get-BotToken -token $token;
		$URL_API = "https://api.telegram.org/bot$($token)/getUpdates"
		
		
		$Params = @{};
		
		if($offset){
			$Params.add("offset", $offset);
		}
		
		if($limit){
			$Params.add("limit", $limit);
		}
		
		if($timeout){
			$Params.add("timeout", $timeout);
		}
		
		if($allowed_updates){
			$Params.add("allowed_updates",$allowed_updates);
		}
		
		$APIResponse = PSTelegramBot_CallTelegramURL -Url $URL_API -Data $Params
		
		return (PSTelegramBot_TranslateResponseJson $APIResponse);
	}

	# Implementation of sendMessage
	# https://core.telegram.org/bots/api#sendmessage
	function Send-TelegramMessage {
		[CmdLetBinding()]
		param(
			[string]$token
			,[string]$chat_id
			,[string]$text 
			,[int]$reply_to_message_id = $null
			,[hashtable]$reply_markup = $null
		)
		
		$token = Get-BotToken -token $token;
		$URL_API = "https://api.telegram.org/bot$($token)/sendMessage"
		
		$Params = @{
			chat_id = $chat_id
			text 	= $text
		}
		
		if($reply_to_message_id){
			$Params.add("reply_to_message_id",$reply_to_message_id);
		}
		
		if($reply_markup){
			$Params.add("reply_markup", $reply_markup);
		}
		
		$APIResponse = PSTelegramBot_CallTelegramURL -Url $URL_API -Data $Params
		
		return (PSTelegramBot_TranslateResponseJson $APIResponse);
	}
	
	# Implementation of keyboard
	# https://core.telegram.org/bots/api#sendmessage
	function New-TelegramReplyKeyboard {
			param(
				 [object[]]$keys
				,[switch]$Resize = $false
				,[switch]$OneTime = $false
				,[switch]$Selective = $false
				
			)
			
			return @{
				keyboard  			= $keys
				resize_keyboard		= [bool]$Resize
				one_time_keyboard	= [bool]$OneTime
				selective			= [bool]$Selective 
			}
	}
	
	# Implementation of SendChataction
	# https://core.telegram.org/bots/api#sendChatAction
	function Send-TelegramChatAction {
			[CmdLetBinding()]
			param(
				 [string]$token
				,[string]$chat_id
				,[string]$action
				
			)
			
		$token = Get-BotToken -token $token;
		$URL_API = "https://api.telegram.org/bot$($token)/sendChatAction"
		
		$Params = @{
			chat_id = $chat_id
			text 	= $text
			action 	= $action
		}
		
		$APIResponse = PSTelegramBot_CallTelegramURL -Url $URL_API -Data $Params
		
		return (PSTelegramBot_TranslateResponseJson $APIResponse);
	}
		
	# Implementation of getFile
	# https://core.telegram.org/bots/api#getfile
	function Get-TelegramFile {
		[CmdLetBinding()]
		param(
			[string]$token
			,[string]$file_id
		)
		
		$token = Get-BotToken -token $token;
		$URL_API = "https://api.telegram.org/bot$($token)/getFile"
		
		
		$Params = @{
			file_id = $file_id
		};
		
		$APIResponse = PSTelegramBot_CallTelegramURL -Url $URL_API -Data $Params
		
		return (PSTelegramBot_TranslateResponseJson $APIResponse);
	}

	
	# Implementation of g
	# https://core.telegram.org/bots/api#getme
	function Get-TelegramMe {
		[CmdLetBinding()]
		param(
			[string]$token = $null
		)
		
		$token = Get-BotToken -token $token;
		$URL_API = "https://api.telegram.org/bot$($token)/getMe"
		
		
		$APIResponse = PSTelegramBot_CallTelegramURL -Url $URL_API -Data @{}
		
		return (PSTelegramBot_TranslateResponseJson $APIResponse);
	}
	
	
############### ADDITIONAL IMPLEMENTATIONS
## Tis is useful to extended telegram capabilities

	#Starts telegram action in async way and keeps sending the action...
	function Start-TelegramChatAction {
		param(
			 $token 
			,$chat_id
			,$action
			,$delay = 5000
		)
		
	
		
		$PsEngine = [Powershell]::Create();
		$Rsp = [RunspaceFactory]::CreateRunspace($Host);
		[void]($Rsp.Open());
		$PsEngine.Runspace = $Rsp;
		
		$Options = New-Object PsObject -Prop @{
			chat_id = $chat_id
			action 	= $action
			delay 	= $delay
			token 	= (Get-BotToken $token)
			_run	= $true
			_powershell = $PsEngine
			_AsyncHandler = $null
			CurrentModule = $MyInvocation.MyCommand.module.path;
		}
		
		
		
		[void]$PsEngine.AddScript({
				param($opts)
				$ErrorActionPreference = "Stop";
				import-module $opts.CurrentModule;
				
				while($opts._run){
					$output = Send-TelegramChatAction -token $opts.token -chat_id $opts.chat_id -action $opts.action
					Start-sleep -m $opts.delay
				}
			}).AddArgument(
				$Options
			)
		
		$Options._AsyncHandler = $PsEngine.BeginInvoke();
		return $Options
	}

	function Stop-TelegramChatAction {
		[CmdLetBinding()]
		param(
			$ActionObject
			,[switch]$Destroy
		)
		
		$ActionObject._run = $false;
		
		if($Destroy){
			$resulsts = $ActionObject._powershell.EndInvoke($ActionObject._AsyncHandler);
			$ActionObject._powershell.Dispose();
		}
	}



	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
