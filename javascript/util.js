var border = new Array();
border.s = "Solid";
border.d = "Dashed";
border.b = "Beveled";
border.i = "Inset";
border.u = "Underline";
var color = new Array();
color.transparent = [ "T" ];
color.black = [ "G", 0];
color.white = [ "G", 1];
color.red = [ "RGB", 1,0,0 ];
color.green = [ "RGB", 0,1,0 ];
color.blue = [ "RGB", 0,0,1 ];
color.cyan = [ "CMYK", 1,0,0,0 ];
color.magenta = [ "CMYK", 0,1,0,0 ];
color.yellow = [ "CMYK", 0,0,1,0 ];
color.dkGray = [ "G", 0.25];
color.gray = [ "G", 0.5];
color.ltGray = [ "G", 0.75];

function AFNumber_Format(nDec,sepStyle,negStyle,currStyle,strCurrency,bCurrencyPrepend)
{
	var val = event.value;
	var fracpart;
	var intpart;
	var point = sepStyle&2 ? ',' : '.';
	var separator = sepStyle&2 ? '.' : ',';

	if (/^\D*\./.test(val))
		val = '0'+val;

	var groups = val.match(/\d+/g);

	switch (groups.length)
	{
	case 0:
		return;
	case 1:
		fracpart = '';
		intpart = groups[0];
		break;
	default:
		fracpart = groups.pop();
		intpart = groups.join('');
		break;
	}

	// Remove leading zeros
	intpart = intpart.replace(/^0*/,'');
	if (!intpart)
		intpart = '0';

	if ((sepStyle & 1) == 0)
	{
		// Add the thousands sepearators: pad to length multiple of 3 with zeros,
		// split into 3s, join with separator, and remove the leading zeros
		intpart = new Array(2-(intpart.length+2)%3+1).join('0') + intpart;
		intpart = intpart.match(/.../g).join(separator).replace(/^0*/,'');
	}

	if (!intpart)
		intpart = '0';

	// Adjust fractional part to correct number of decimal places
	fracpart += new Array(nDec+1).join('0');
	fracpart = fracpart.substr(0,nDec);

	if (fracpart)
		intpart += point+fracpart;

	if (bCurrencyPrepend)
		intpart = strCurrency+intpart;
	else
		intpart += strCurrency;

	if (/-/.test(val))
	{
		switch (negStyle)
		{
		case 0:
			intpart = '-'+intpart;
			break;
		case 1:
			break;
		case 2:
		case 3:
			intpart = '('+intpart+')';
			break;
		}
	}

	if (negStyle&1)
		event.target.textColor = /-/.text(val) ? color.red : color.black;

	event.value = intpart;
}

function AFSimple_Calculate(op, list)
{
	var res;

	switch (op)
	{
		case 'SUM':
			res = 0;
			break;
		case 'PRD':
			res = 1;
			break;
		case 'AVG':
			res = 0;
			break;
	}

	if (typeof list == 'string')
		list = list.split(/ *, */);

	for (var i = 0; i < list.length; i++)
	{
		var field = getField(list[i]);
		var value = Number(field.value);

		switch (op)
		{
			case 'SUM':
				res += value;
				break;
			case 'PRD':
				res *= value;
				break;
			case 'AVG':
				res += value;
				break;
			case 'MIN':
				if (i == 0 || value < res)
					res = value;
				break;
			case 'MAX':
				if (i == 0 || value > res)
					res = value;
				break;
		}
	}

	if (op == 'AVG')
		res /= list.length;

	event.value = res;
}
