Error.prototype.toString = function() {
	if (this.stackTrace) return this.name + ': ' + this.message + this.stackTrace;
	return this.name + ': ' + this.message;
};

var MuPDF = {
	monthPattern: /Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec/i,
	monthName: [
		'January',
		'February',
		'March',
		'April',
		'May',
		'June',
		'July',
		'August',
		'September',
		'October',
		'November',
		'December'
	],
	shortMonthName: [
		'jan',
		'feb',
		'mar',
		'apr',
		'may',
		'jun',
		'jul',
		'aug',
		'sep',
		'oct',
		'nov',
		'dec'
	],
	dayName: [
		'Sunday',
		'Monday',
		'Tuesday',
		'Wednesday',
		'Thursday',
		'Friday',
		'Saturday'
	],
	dateFormats: [
		'm/d',
		'm/d/yy',
		'mm/dd/yy',
		'mm/yy',
		'd-mmm',
		'd-mmm-yy',
		'dd-mm-yy',
		'yy-mm-dd',
		'mmm-yy',
		'mmmm-yy',
		'mmm d, yyyy',
		'mmmm d, yyyy',
		'm/d/yy h:MM tt',
		'm/d/yy HH:MM'
	],
	timeFormats: [
		'HH:MM',
		'h:MM tt',
		'HH:MM:ss',
		'h:MM:ss tt'
	],
};

// display must be kept in sync with an enum in pdf_form.c
var display = {
	visible: 0,
	hidden: 1,
	noPrint: 2,
	noView: 3,
};

var border = {
	b: 'beveled',
	d: 'dashed',
	i: 'inset',
	s: 'solid',
	u: 'underline',
};

var color = {
	transparent: [ 'T' ],
	black: [ 'G', 0 ],
	white: [ 'G', 1 ],
	gray: [ 'G', 0.5 ],
	ltGray: [ 'G', 0.75 ],
	dkGray: [ 'G', 0.25 ],
	red: [ 'RGB', 1, 0, 0 ],
	green: [ 'RGB', 0, 1, 0 ],
	blue: [ 'RGB', 0, 0, 1 ],
	cyan: [ 'CMYK', 1, 0, 0, 0 ],
	magenta: [ 'CMYK', 0, 1, 0, 0 ],
	yellow: [ 'CMYK', 0, 0, 1, 0 ],
};

color.convert = function (c, colorspace) {
	switch (colorspace) {
	case 'G':
		if (c[0] === 'RGB')
			return [ 'G', c[1] * 0.3 + c[2] * 0.59 + c[3] * 0.11 ];
		if (c[0] === 'CMYK')
			return [ 'CMYK', 1 - Math.min(1, c[1] * 0.3 + c[2] * 0.59 + c[3] * 0.11 + c[4])];
		break;
	case 'RGB':
		if (c[0] === 'G')
			return [ 'RGB', c[1], c[1], c[1] ];
		if (c[0] === 'CMYK')
			return [ 'RGB',
				1 - Math.min(1, c[1] + c[4]),
				1 - Math.min(1, c[2] + c[4]),
				1 - Math.min(1, c[3] + c[4]) ];
		break;
	case 'CMYK':
		if (c[0] === 'G')
			return [ 'CMYK', 0, 0, 0, 1 - c[1] ];
		if (c[0] === 'RGB')
			return [ 'CMYK', 1 - c[1], 1 - c[2], 1 - c[3], 0 ];
		break;
	}
	return c;
}

color.equal = function (a, b) {
	var i, n
	if (a[0] === 'G')
		a = color.convert(a, b[0]);
	else
		b = color.convert(b, a[0]);
	if (a[0] !== b[0])
		return false;
	switch (a[0]) {
	case 'G': n = 1; break;
	case 'RGB': n = 3; break;
	case 'CMYK': n = 4; break;
	default: n = 0; break;
	}
	for (i = 1; i <= n; ++i)
		if (a[i] !== b[i])
			return false;
	return true;
}

var font = {
	Cour: 'Courier',
	CourB: 'Courier-Bold',
	CourBI: 'Courier-BoldOblique',
	CourI: 'Courier-Oblique',
	Helv: 'Helvetica',
	HelvB: 'Helvetica-Bold',
	HelvBI: 'Helvetica-BoldOblique',
	HelvI: 'Helvetica-Oblique',
	Symbol: 'Symbol',
	Times: 'Times-Roman',
	TimesB: 'Times-Bold',
	TimesBI: 'Times-BoldItalic',
	TimesI: 'Times-Italic',
	ZapfD: 'ZapfDingbats',
};

var highlight = {
	i: 'invert',
	n: 'none',
	o: 'outline',
	p: 'push',
};

var position = {
	textOnly: 0,
	iconOnly: 1,
	iconTextV: 2,
	textIconV: 3,
	iconTextH: 4,
	textIconH: 5,
	overlay: 6,
};

var scaleHow = {
	proportional: 0,
	anamorphic: 1,
};

var scaleWhen = {
	always: 0,
	never: 1,
	tooBig: 2,
	tooSmall: 3,
};

var style = {
	ch: 'check',
	ci: 'circle',
	cr: 'cross',
	di: 'diamond',
	sq: 'square',
	st: 'star',
};

var zoomtype = {
	fitH: 'FitHeight',
	fitP: 'FitPage',
	fitV: 'FitVisibleWidth',
	fitW: 'FitWidth',
	none: 'NoVary',
	pref: 'Preferred',
	refW: 'ReflowWidth',
};

util.printd = function (fmt, d) {
	function padZeros(num, places) {
		var s = String(num)
		while (s.length < places)
			s = '0' + s;
		return s;
	}
	if (!d) return null;
	var res = '';
	var tokens = fmt.match(/(m+|d+|y+|H+|h+|M+|s+|t+|[^mdyHhMst]+)/g);
	var length = tokens ? tokens.length : 0;
	var i;
	for (i = 0; i < length; ++i) {
		switch (tokens[i]) {
		case 'mmmm': res += MuPDF.monthName[d.getMonth()]; break;
		case 'mmm': res += MuPDF.monthName[d.getMonth()].substring(0, 3); break;
		case 'mm': res += padZeros(d.getMonth()+1, 2); break;
		case 'm': res += d.getMonth()+1; break;
		case 'dddd': res += MuPDF.dayName[d.getDay()]; break;
		case 'ddd': res += MuPDF.dayName[d.getDay()].substring(0, 3); break;
		case 'dd': res += padZeros(d.getDate(), 2); break;
		case 'd': res += d.getDate(); break;
		case 'yyyy': res += d.getFullYear(); break;
		case 'yy': res += d.getFullYear()%100; break;
		case 'HH': res += padZeros(d.getHours(), 2); break;
		case 'H': res += d.getHours(); break;
		case 'hh': res += padZeros((d.getHours()+11)%12+1, 2); break;
		case 'h': res += (d.getHours()+11)%12+1; break;
		case 'MM': res += padZeros(d.getMinutes(), 2); break;
		case 'M': res += d.getMinutes(); break;
		case 'ss': res += padZeros(d.getSeconds(), 2); break;
		case 's': res += d.getSeconds(); break;
		case 'tt': res += d.getHours() < 12 ? 'am' : 'pm'; break;
		case 't': res += d.getHours() < 12 ? 'a' : 'p'; break;
		default: res += tokens[i];
		}
	}
	return res;
}

util.printx = function (fmt, val) {
	function convertCase(str, cmd) {
		switch (cmd) {
		case '>': return str.toUpperCase();
		case '<': return str.toLowerCase();
		default: return str;
		}
	}
	var cs = '=';
	var res = '';
	var i, m;
	var length = fmt ? fmt.length : 0;
	for (i = 0; i < length; ++i) {
		switch (fmt.charAt(i)) {
		case '\\':
			if (++i < length)
				res += fmt.charAt(i);
			break;
		case 'X':
			m = val.match(/\w/);
			if (m) {
				res += convertCase(m[0], cs);
				val = val.replace(/^\W*\w/, '');
			}
			break;
		case 'A':
			m = val.match(/[A-Za-z]/);
			if (m) {
				res += convertCase(m[0], cs);
				val = val.replace(/^[^A-Za-z]*[A-Za-z]/, '');
			}
			break;
		case '9':
			m = val.match(/\d/);
			if (m) {
				res += m[0];
				val = val.replace(/^\D*\d/, '');
			}
			break;
		case '*':
			res += val;
			val = '';
			break;
		case '?':
			if (val) {
				res += convertCase(val.charAt(0), cs);
				val = val.substring(1);
			}
			break;
		case '=':
		case '>':
		case '<':
			cs = fmt.charAt(i);
			break;
		default:
			res += convertCase(fmt.charAt(i), cs);
			break;
		}
	}
	return res;
}

function AFMergeChange(event) {
	var prefix, postfix;
	var value = event.value;
	if (event.willCommit)
		return value;
	if (event.selStart >= 0)
		prefix = value.substring(0, event.selStart);
	else
		prefix = '';
	if (event.selEnd >= 0 && event.selEnd <= value.length)
		postfix = value.substring(event.selEnd, value.length);
	else
		postfix = '';
	return prefix + event.change + postfix;
}

function AFExtractNums(string) {
	if (string.charAt(0) == '.' || string.charAt(0) == ',')
		string = '0' + string;
	return string.match(/\d+/g);
}

function AFMakeNumber(string) {
	if (typeof string == 'number')
		return string;
	if (typeof string != 'string')
		return null;
	var nums = AFExtractNums(string);
	if (!nums)
		return null;
	var result = nums.join('.');
	if (string.indexOf('-.') >= 0)
		result = '0.' + result;
	if (string.indexOf('-') >= 0)
		return -result;
	return result;
}

function AFExtractTime(dt) {
	var ampm = dt.match(/(am|pm)/);
	dt = dt.replace(/(am|pm)/, '');
	var t = dt.match(/\d{1,2}:\d{1,2}:\d{1,2}/);
	dt = dt.replace(/\d{1,2}:\d{1,2}:\d{1,2}/, '');
	if (!t) {
		t = dt.match(/\d{1,2}:\d{1,2}/);
		dt = dt.replace(/\d{1,2}:\d{1,2}/, '');
	}
	return [dt, t?t[0]+(ampm?ampm[0]:''):''];
}

function AFParseDateOrder(fmt) {
	var i;
	var order = '';

	// Ensure all present with those not added in default order
	fmt += 'mdy';

	for (i = 0; i < fmt.length; i++) {
		var c = fmt.charAt(i);
		if ('ymd'.indexOf(c) !== -1 && order.indexOf(c) === -1)
			order += c;
	}

	return order;
}

function AFMatchMonth(d) {
	var m = d.match(MuPDF.monthPattern);
	return m ? MuPDF.shortMonthName.indexOf(m[0].toLowerCase()) : null;
}

function AFParseTime(str, d) {
	if (!str)
		return d;

	if (!d)
		d = new Date();

	var ampm = str.match(/(am|pm)/);
	var nums = str.match(/\d+/g);
	var hour, min, sec;

	if (!nums)
		return null;

	sec = 0;

	switch (nums.length) {
	case 3:
		sec = parseInt(nums[2]);
	case 2:
		hour = parseInt(nums[0]);
		min = parseInt(nums[1]);
		break;
	default:
		return null;
	}

	ampm = ampm && ampm[0]

	if (ampm === 'am' && hour < 12)
		hour = 12 + hour;
	if (ampm === 'pm' && hour >= 12)
		hour = 0 + hour - 12;

	d.setHours(hour, min, sec);

	if (d.getHours() !== hour || d.getMinutes() !== min || d.getSeconds() !== sec)
		return null;

	return d;
}

function AFParseDateEx(d, fmt) {
	var i;
	var dt = AFExtractTime(d);
	var nums = dt[0].match(/\d+/g);
	var order = AFParseDateOrder(fmt);
	var text_month = AFMatchMonth(dt[0]);
	var dout = new Date();
	var year = dout.getFullYear();
	var month = dout.getMonth();
	var date = dout.getDate();

	dout.setHours(12, 0, 0);

	if (!nums)
		return null;

	if (nums.length == 1 && nums[0].length == fmt.length && !text_month) {
		// One number string, exactly matching the format string in length.
		// Split it into separate strings to match the fmt
		var num = nums[0];
		nums = [''];
		for (i = 0; i < fmt.length; i++)
		{
			nums[nums.length-1] += num.charAt(i);
			if (i+1 < fmt.length && fmt.charAt(i) != fmt.charAt(i+1))
				nums.push('');
		}
	}

	// Need at least two parts of the date, but one
	// can come from text_month. text_month is
	// ignored if we have three numbers.
	var total = nums.length + (text_month ? 1 : 0);

	if (total < 2 || nums.length > 3)
		return null;

	if (nums.length < 3 && text_month) {
		// Use the text month rather than one of the numbers
		month = text_month;
		order = order.replace('m', '');
	}

	order = order.substring(0, nums.length);

	// If year and month specified but not date then use the 1st
	if (order === 'ym' || order === 'my' || (order === 'y' && text_month))
		date = 1;

	for (i = 0; i < nums.length; i++) {
		switch (order.charAt(i)) {
		case 'y': year = parseInt(nums[i]); break;
		case 'm': month = parseInt(nums[i]) - 1; break;
		case 'd': date = parseInt(nums[i]); break;
		}
	}

	if (year < 100) {
		if (fmt.search('yyyy') !== -1)
			return null;
		if (year >= 50)
			year = 1900 + year;
		else if (year >= 0)
			year = 2000 + year;
	}

	dout.setFullYear(year, month, date);

	if (dout.getFullYear() !== year || dout.getMonth() !== month || dout.getDate() !== date)
		return null;

	return AFParseTime(dt[1], dout);
}

function AFDate_KeystrokeEx(fmt) {
	if (event.willCommit && !AFParseDateEx(event.value, fmt)) {
		app.alert('The date/time entered ('+event.value+') does not match the format ('+fmt+') of the field [ '+event.target.name+' ]');
		event.rc = false;
	}
}

function AFDate_Keystroke(index) {
	AFDate_KeystrokeEx(MuPDF.dateFormats[index]);
}

function AFDate_FormatEx(fmt) {
	var d = AFParseDateEx(event.value, fmt);
	event.value = d ? util.printd(fmt, d) : '';
}

function AFDate_Format(index) {
	AFDate_FormatEx(MuPDF.dateFormats[index]);
}

function AFTime_Keystroke(index) {
	if (event.willCommit && !AFParseTime(event.value, null)) {
		app.alert('The value entered ('+event.value+') does not match the format of the field [ '+event.target.name+' ]');
		event.rc = false;
	}
}

function AFTime_FormatEx(fmt) {
	var d = AFParseTime(event.value, null);
	event.value = d ? util.printd(fmt, d) : '';
}

function AFTime_Format(index) {
	AFTime_FormatEx(MuPDF.timeFormats[index]);
}

function AFSpecial_KeystrokeEx(fmt) {
	var cs = '=';
	var val = event.value;
	var res = '';
	var i = 0;
	var m;
	var length = fmt ? fmt.length : 0;

	function convertCase(str, cmd) {
		switch (cmd) {
		case '>': return str.toUpperCase();
		case '<': return str.toLowerCase();
		default: return str;
		}
	}

	while (i < length) {
		switch (fmt.charAt(i)) {
		case '\\':
			i++;
			if (i >= length)
				break;
			res += fmt.charAt(i);
			if (val && val.charAt(0) === fmt.charAt(i))
				val = val.substring(1);
			break;

		case 'X':
			m = val.match(/^\w/);
			if (!m) {
				event.rc = false;
				break;
			}
			res += convertCase(m[0], cs);
			val = val.substring(1);
			break;

		case 'A':
			m = val.match(/^[A-Za-z]/);
			if (!m) {
				event.rc = false;
				break;
			}
			res += convertCase(m[0], cs);
			val = val.substring(1);
			break;

		case '9':
			m = val.match(/^\d/);
			if (!m) {
				event.rc = false;
				break;
			}
			res += m[0];
			val = val.substring(1);
			break;

		case '*':
			res += val;
			val = '';
			break;

		case '?':
			if (!val) {
				event.rc = false;
				break;
			}
			res += convertCase(val.charAt(0), cs);
			val = val.substring(1);
			break;

		case '=':
		case '>':
		case '<':
			cs = fmt.charAt(i);
			break;

		default:
			res += fmt.charAt(i);
			if (val && val.charAt(0) === fmt.charAt(i))
				val = val.substring(1);
			break;
		}

		i++;
	}

	//  If there are characters left over in the value, it's not a match.
	if (val.length > 0)
		event.rc = false;

	if (event.rc)
		event.value = res;
	else if (event.willCommit)
		app.alert('The value entered ('+event.value+') does not match the format of the field [ '+event.target.name+' ] should be '+fmt);
}

function AFSpecial_Keystroke(index) {
	if (event.willCommit) {
		switch (index) {
		case 0:
			if (!event.value.match(/^\d{5}$/))
				event.rc = false;
			break;
		case 1:
			if (!event.value.match(/^\d{5}[-. ]?\d{4}$/))
				event.rc = false;
			break;
		case 2:
			if (!event.value.match(/^((\(\d{3}\)|\d{3})[-. ]?)?\d{3}[-. ]?\d{4}$/))
				event.rc = false;
			break;
		case 3:
			if (!event.value.match(/^\d{3}[-. ]?\d{2}[-. ]?\d{4}$/))
				event.rc = false;
			break;
		}
		if (!event.rc)
			app.alert('The value entered ('+event.value+') does not match the format of the field [ '+event.target.name+' ]');
	}
}

function AFSpecial_Format(index) {
	var res;
	switch (index) {
	case 0:
		res = util.printx('99999', event.value);
		break;
	case 1:
		res = util.printx('99999-9999', event.value);
		break;
	case 2:
		res = util.printx('9999999999', event.value);
		res = util.printx(res.length >= 10 ? '(999) 999-9999' : '999-9999', event.value);
		break;
	case 3:
		res = util.printx('999-99-9999', event.value);
		break;
	}
	event.value = res ? res : '';
}

function AFNumber_Keystroke(nDec, sepStyle, negStyle, currStyle, strCurrency, bCurrencyPrepend) {
	if (sepStyle & 2) {
		if (!event.value.match(/^[+-]?\d*[,.]?\d*$/))
			event.rc = false;
	} else {
		if (!event.value.match(/^[+-]?\d*\.?\d*$/))
			event.rc = false;
	}
	if (event.willCommit) {
		if (!event.value.match(/\d/))
			event.rc = false;
		if (!event.rc)
			app.alert('The value entered ('+event.value+') does not match the format of the field [ '+event.target.name+' ]');
	}
}

function AFNumber_Format(nDec, sepStyle, negStyle, currStyle, strCurrency, bCurrencyPrepend) {
	var value = AFMakeNumber(event.value);
	var fmt = '%,' + sepStyle + '.' + nDec + 'f';
	console.println('AFNumber_Format', fmt, value);
	if (value == null) {
		event.value = '';
		return;
	}
	if (bCurrencyPrepend)
		fmt = strCurrency + fmt;
	else
		fmt = fmt + strCurrency;
	if (value < 0) {
		/* negStyle: 0=MinusBlack, 1=Red, 2=ParensBlack, 3=ParensRed */
		value = Math.abs(value);
		if (negStyle == 2 || negStyle == 3)
			fmt = '(' + fmt + ')';
		else if (negStyle == 0)
			fmt = '-' + fmt;
		if (negStyle == 1 || negStyle == 3)
			event.target.textColor = color.red;
		else
			event.target.textColor = color.black;
	} else {
		event.target.textColor = color.black;
	}
	event.value = util.printf(fmt, value);
}

function AFPercent_Keystroke(nDec, sepStyle) {
	AFNumber_Keystroke(nDec, sepStyle, 0, 0, '', true);
}

function AFPercent_Format(nDec, sepStyle) {
	var val = AFMakeNumber(event.value);
	if (val == null) {
		event.value = '';
		return;
	}
	event.value = (val * 100) + '';
	AFNumber_Format(nDec, sepStyle, 0, 0, '%', false);
}

function AFSimple_Calculate(op, list) {
	var i, res;

	switch (op) {
	case 'SUM': res = 0; break;
	case 'PRD': res = 1; break;
	case 'AVG': res = 0; break;
	}

	if (typeof list === 'string')
		list = list.split(/ *, */);

	for (i = 0; i < list.length; i++) {
		var field = this.getField(list[i]);
		var value = Number(field.value);
		switch (op) {
		case 'SUM': res += value; break;
		case 'PRD': res *= value; break;
		case 'AVG': res += value; break;
		case 'MIN': if (i === 0 || value < res) res = value; break;
		case 'MAX': if (i === 0 || value > res) res = value; break;
		}
	}

	if (op === 'AVG')
		res /= list.length;

	event.value = res;
}

function AFRange_Validate(lowerCheck, lowerLimit, upperCheck, upperLimit) {
	if (upperCheck && event.value > upperLimit)
		event.rc = false;
	if (lowerCheck && event.value < lowerLimit)
		event.rc = false;
	if (!event.rc) {
		if (lowerCheck && upperCheck)
			app.alert(util.printf('The entered value ('+event.value+') must be greater than or equal to %s and less than or equal to %s', lowerLimit, upperLimit));
		else if (lowerCheck)
			app.alert(util.printf('The entered value ('+event.value+') must be greater than or equal to %s', lowerLimit));
		else
			app.alert(util.printf('The entered value ('+event.value+') must be less than or equal to %s', upperLimit));
	}
}

/* Compatibility ECMAScript functions */
String.prototype.substr = function (start, length) {
	if (start < 0)
		start = this.length + start;
	if (length === undefined)
		return this.substring(start, this.length);
	return this.substring(start, start + length);
}
Date.prototype.getYear = Date.prototype.getFullYear;
Date.prototype.setYear = Date.prototype.setFullYear;
Date.prototype.toGMTString = Date.prototype.toUTCString;

console.clear = function() { console.println('--- clear console ---\n'); };
console.show = function(){};
console.hide = function(){};

app.plugIns = [];
app.viewerType = 'Reader';
app.language = 'ENU';
app.viewerVersion = NaN;
