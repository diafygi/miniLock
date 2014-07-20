miniLock.templates = {}

miniLock.templates.keyStrengthMoreInfo = 'Key is too weak. '
	+ '<span class="keyStrengthMoreInfo">Help me pick a key!</span>'
	+ '<p>Having a long, unique key is very important for using miniLock. '
	+ 'Try using a <strong>phrase</strong> that makes sense only to you.</p>'
	+ '<p>miniLock can generate a	 phrase for you to use as a key:<br />'
	+ '<input type="text" value="{{phrase}}" spellcheck="false" readonly="readonly" />'
	+ '<input type="button" value="Get another phrase" /></p>'
	+ '<p>Alternatively, a password manager can generate passwords for you:<br />'
	+ 'Examples:'
	+ ' <a href="http://keepass.info/" target="_blank">KeePass</a>'
	+ ' <a href="https://lastpass.com/" target="_blank">LastPass</a>'
	+ ' <a href="https://agilebits.com/onepassword" target="_blank">1Password</a></p>'

miniLock.templates.recipient = '<input type="text" val="" placeholder="Recipient\'s miniLock ID" />'
