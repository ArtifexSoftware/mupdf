import codecs
#import doctest # This import is slow, so we only import when necessary.
import inspect
import io
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import textwrap
import time
import traceback
import types
import typing


def place( frame_record=1):
    '''
    Useful debugging function - returns representation of source position of
    caller.

    frame_record:
        Integer number of frames up stack, or a FrameInfo (for example from
        inspect.stack()).
    '''
    if isinstance( frame_record, int):
        frame_record = inspect.stack( context=0)[ frame_record+1]
    filename    = frame_record.filename
    line        = frame_record.lineno
    function    = frame_record.function
    ret = os.path.split( filename)[1] + ':' + str( line) + ':' + function + ':'
    if 0:   # lgtm [py/unreachable-statement]
        tid = str( threading.currentThread())
        ret = '[' + tid + '] ' + ret
    return ret


def expand_nv( text, caller=1):
    '''
    Returns <text> with special handling of {<expression>} items.

    text:
        String containing {<expression>} items.
    caller:
        If an int, the number of frames to step up when looking for file:line
        information or evaluating expressions.

        Otherwise should be a frame record as returned by inspect.stack()[].

    <expression> is evaluated in <caller>'s context using eval(), and expanded
    to <expression> or <expression>=<value>.

    If <expression> ends with '=', this character is removed and we prefix the
    result with <expression>=.

    >>> x = 45
    >>> y = 'hello'
    >>> expand_nv( 'foo {x} {y=}')
    "foo 45 y='hello'"

    <expression> can also use ':' and '!' to control formatting, like
    str.format().

    >>> x = 45
    >>> y = 'hello'
    >>> expand_nv( 'foo {x} {y!r=}')
    "foo 45 y='hello'"

    If <expression> starts with '=', this character is removed and we show each
    space-separated item in the remaining text as though it was appended with
    '='.

    >>> foo = 45
    >>> y = 'hello'
    >>> expand_nv('{=foo y}')
    "foo=45 y='hello'"
    '''
    if isinstance( caller, int):
        frame_record = inspect.stack()[ caller]
    else:
        frame_record = caller
    frame = frame_record.frame
    try:
        def get_items():
            '''
            Yields (pre, item), where <item> is contents of next {...} or None,
            and <pre> is preceding text.
            '''
            pos = 0
            pre = ''
            while 1:
                if pos == len( text):
                    yield pre, None
                    break
                rest = text[ pos:]
                if rest.startswith( '{{') or rest.startswith( '}}'):
                    pre += rest[0]
                    pos += 2
                elif text[ pos] == '{':
                    close = text.find( '}', pos)
                    if close < 0:
                        raise Exception( 'After "{" at offset %s, cannot find closing "}". text is: %r' % (
                                pos, text))
                    text2 = text[ pos+1 : close]
                    if text2.startswith('='):
                        text2 = text2[1:]
                        for i, text3 in enumerate(text2.split()):
                            pre2 = ' ' if i else pre
                            yield pre2, text3 + '='
                    else:
                        yield pre, text[ pos+1 : close]
                    pre = ''
                    pos = close + 1
                else:
                    pre += text[ pos]
                    pos += 1

        ret = ''
        for pre, item in get_items():
            ret += pre
            nv = False
            if item:
                if item.endswith( '='):
                    nv = True
                    item = item[:-1]
                expression, tail = split_first_of( item, '!:')
                if expression.endswith('='):
                    # Basic PEP 501 support.
                    nv = True
                    expression = expression[:-1]
                if not tail:
                    # Default to !r as in PEP 501.
                    tail = '!r'
                try:
                    value = eval( expression, frame.f_globals, frame.f_locals)
                    value_text = ('{0%s}' % tail).format( value)
                except Exception as e:
                    value_text = '{??Failed to evaluate %r in context %s:%s; expression=%r tail=%r: %s}' % (
                            expression,
                            frame_record.filename,
                            frame_record.lineno,
                            expression,
                            tail,
                            e,
                            )
                if nv:
                    ret += '%s=' % expression
                ret += value_text

        return ret

    finally:
        del frame   # lgtm [py/unnecessary-delete]


class LogPrefixTime:
    def __init__( self, date=False, time_=True, elapsed=False):
        self.date = date
        self.time = time_
        self.elapsed = elapsed
        self.t0 = time.time()
    def __call__( self):
        ret = ''
        if self.date:
            ret += time.strftime( ' %F')
        if self.time:
            ret += time.strftime( ' %T')
        if self.elapsed:
            ret += ' (+%s)' % time_duration( time.time() - self.t0, s_format='%.1f')
        if ret:
            ret = ret.strip() + ': '
        return ret

class LogPrefixFileLine:
    def __call__( self, caller):
        if isinstance( caller, int):
            caller = inspect.stack()[ caller]
        return place( caller) + ' '

class LogPrefixScopes:
    '''
    Internal use only.
    '''
    def __init__( self):
        self.items = []
    def __call__( self):
        ret = ''
        for item in self.items:
            if callable( item):
                item = item()
            ret += item
        return ret


class LogPrefixScope:
    '''
    Can be used to insert scoped prefix to log output.
    '''
    def __init__( self, prefix):
        self.prefix = prefix
    def __enter__( self):
        g_log_prefix_scopes.items.append( self.prefix)
    def __exit__( self, exc_type, exc_value, traceback):
        global g_log_prefix
        g_log_prefix_scopes.items.pop()


g_log_delta = 0

class LogDeltaScope:
    '''
    Can be used to temporarily change verbose level of logging.

    E.g to temporarily increase logging:

        with jlib.LogDeltaScope(-1):
            ...
    '''
    def __init__( self, delta):
        self.delta = delta
        global g_log_delta
        g_log_delta += self.delta
    def __enter__( self):
        pass
    def __exit__( self, exc_type, exc_value, traceback):
        global g_log_delta
        g_log_delta -= self.delta

# Special item that can be inserted into <g_log_prefixes> to enable
# temporary addition of text into log prefixes.
#
g_log_prefix_scopes = LogPrefixScopes()

# List of items that form prefix for all output from log().
#
g_log_prefixes = [
        LogPrefixTime( time_=False, elapsed=True),
        g_log_prefix_scopes,
        LogPrefixFileLine(),
        ]


_log_text_line_start = True

def log_text( text=None, caller=1, nv=True, raw=False, nl=True):
    '''
    Returns log text, prepending all lines with text from g_log_prefixes.

    text:
        The text to output. Each line is prepended with prefix text.
    caller:
        If an int, the number of frames to step up when looking for file:line
        information or evaluating expressions.

        Otherwise should be a frame record as returned by inspect.stack()[].
    nv:
        If true, we expand {...} in <text> using expand_nv().
    nl:
        If true (the default) we terminate text with a newline if not already
        present. Ignored if `raw` is true.
    '''
    if isinstance( caller, int):
        caller += 1
    # Construct line prefix.
    prefix = ''
    for p in g_log_prefixes:
        if callable( p):
            if isinstance( p, LogPrefixFileLine):
                p = p(caller)
            else:
                p = p()
        prefix += p

    if text is None:
        return prefix

    # Expand {...} using our enhanced f-string support.
    if nv:
        text = expand_nv( text, caller)

    # Prefix each line. If <raw> is false, we terminate the last line with a
    # newline. Otherwise we use _log_text_line_start to remember whether we are
    # at the beginning of a line.
    #
    global _log_text_line_start
    text2 = ''
    pos = 0
    while 1:
        if pos == len(text):
            break
        if not raw or _log_text_line_start:
            text2 += prefix
        nl = text.find('\n', pos)
        if nl == -1:
            text2 += text[pos:]
            if not raw and nl:
                text2 += '\n'
            pos = len(text)
        else:
            text2 += text[pos:nl+1]
            pos = nl+1
        if raw:
            _log_text_line_start = (nl >= 0)
    return text2


s_log_levels_cache = dict()
s_log_levels_items = []

def log_levels_find( caller):
    if not s_log_levels_items:
        return 0

    tb = traceback.extract_stack( None, 1+caller)
    if len(tb) == 0:
        return 0
    filename, line, function, text = tb[0]

    key = function, filename, line,
    delta = s_log_levels_cache.get( key)

    if delta is None:
        # Calculate and populate cache.
        delta = 0
        for item_function, item_filename, item_delta in s_log_levels_items:
            if item_function and not function.startswith( item_function):
                continue
            if item_filename and not filename.startswith( item_filename):
                continue
            delta = item_delta
            break

        s_log_levels_cache[ key] = delta

    return delta


def log_levels_add( delta, filename_prefix, function_prefix):
    '''
    log() calls from locations with filenames starting with <filename_prefix>
    and/or function names starting with <function_prefix> will have <delta>
    added to their level.

    Use -ve delta to increase verbosity from particular filename or function
    prefixes.
    '''
    log( 'adding level: {filename_prefix=!r} {function_prefix=!r}')

    # Sort in reverse order so that long functions and filename specs come
    # first.
    #
    s_log_levels_items.append( (function_prefix, filename_prefix, delta))
    s_log_levels_items.sort( reverse=True)


s_log_out = sys.stdout

def log( text, level=0, caller=1, nv=True, out=None, raw=False):
    '''
    Writes log text, with special handling of {<expression>} items in <text>
    similar to python3's f-strings.

    text:
        The text to output.
    level:
        Lower values are more verbose.
    caller:
        How many frames to step up to get caller's context when evaluating
        file:line information and/or expressions. Or frame record as returned
        by inspect.stack()[].
    nv:
        If true, we expand {...} in <text> using expand_nv().
    out:
        Where to send output. If None we use sys.stdout.
    raw:
        If true we don't ensure output text is terminated with a newline. E.g.
        use by jlib.system() when sending us raw output which is not
        line-based.

    <expression> is evaluated in our caller's context (<n> stack frames up)
    using eval(), and expanded to <expression> or <expression>=<value>.

    If <expression> ends with '=', this character is removed and we prefix the
    result with <expression>=.

    E.g.:
        x = 45
        y = 'hello'
        expand_nv( 'foo {x} {y=}')
    returns:
        foo 45 y=hello

    <expression> can also use ':' and '!' to control formatting, like
    str.format().
    '''
    if out is None:
        out = s_log_out
    level += g_log_delta
    if isinstance( caller, int):
        caller += 1
    level += log_levels_find( caller)
    if level <= 0:
        text = log_text( text, caller, nv=nv, raw=raw)
        try:
            out.write( text)
        except UnicodeEncodeError:
            # Retry, ignoring errors by encoding then decoding with
            # errors='replace'.
            #
            out.write('[***write encoding error***]')
            text_encoded = codecs.encode(text, out.encoding, errors='replace')
            text_encoded_decoded = codecs.decode(text_encoded, out.encoding, errors='replace')
            out.write(text_encoded_decoded)
            out.write('[/***write encoding error***]')
        out.flush()

def log_raw( text, level=0, caller=1, nv=False, out=None):
    '''
    Like log() but defaults to nv=False so any {...} are not evaluated as
    expressions.

    Useful for things like:
        jlib.system(..., out=jlib.log_raw)
    '''
    log( text, level=0, caller=caller+1, nv=nv, out=out)

def log0( text, caller=1, nv=True, out=None):
    '''
    Most verbose log. Same as log().
    '''
    log( text, level=0, caller=caller+1, nv=nv, out=out)

def log1( text, caller=1, nv=True, out=None):
    log( text, level=1, caller=caller+1, nv=nv, out=out)

def log2( text, caller=1, nv=True, out=None):
    log( text, level=2, caller=caller+1, nv=nv, out=out)

def log3( text, caller=1, nv=True, out=None):
    log( text, level=3, caller=caller+1, nv=nv, out=out)

def log4( text, caller=1, nv=True, out=None):
    log( text, level=4, caller=caller+1, nv=nv, out=out)

def log5( text, caller=1, nv=True, out=None):
    '''
    Least verbose log.
    '''
    log( text, level=5, caller=caller+1, nv=nv, out=out)

def logx( text, caller=1, nv=True, out=None):
    '''
    Does nothing, useful when commenting out a log().
    '''
    pass


_log_interval_t0 = 0

def log_interval( text, level=0, caller=1, nv=True, out=None, raw=False, interval=10):
    '''
    Like log() but outputs no more than one diagnostic every <interval>
    seconds, and <text> can be a callable taking no args and returning a
    string.
    '''
    global _log_interval_t0
    t = time.time()
    if t - _log_interval_t0 > interval:
        _log_interval_t0 = t
        if callable( text):
            text = text()
        log( text, level=level, caller=caller+1, nv=nv, out=out, raw=raw)


def log_levels_add_env( name='JLIB_log_levels'):
    '''
    Added log levels encoded in an environmental variable.
    '''
    t = os.environ.get( name)
    if t:
        for ffll in t.split( ','):
            ffl, delta = ffll.split( '=', 1)
            delta = int( delta)
            ffl = ffl.split( ':')
            if 0:   # lgtm [py/unreachable-statement]
                pass
            elif len( ffl) == 1:
                filename = ffl
                function = None
            elif len( ffl) == 2:
                filename, function = ffl
            else:
                assert 0
            log_levels_add( delta, filename, function)


class TimingsItem:
    '''
    Helper for Timings class.
    '''
    def __init__( self, name):
        self.name = name
        self.children = dict()
        self.t_begin = None
        self.t = 0
        self.n = 0
    def begin( self, t):
        assert self.t_begin is None
        self.t_begin = t
    def end( self, t):
        assert self.t_begin is not None, f't_begin is None, .name={self.name}'
        self.t += t - self.t_begin
        self.n += 1
        self.t_begin = None
    def __str__( self):
        return f'[name={self.name} t={self.t} n={self.n} t_begin={self.t_begin}]'
    def __repr__( self):
        return self.__str__()

class Timings:
    '''
    Allows gathering of hierachical timing information. Can also generate useful
    diagnostics.

    Caller can generate a tree of TimingsItem items via our begin() and end() methods.

    >>> ts = Timings()
    >>> ts.begin('a')
    >>> time.sleep(0.1)
    >>> ts.begin('b')
    >>> time.sleep(0.2)
    >>> ts.begin('c')
    >>> time.sleep(0.3)
    >>> ts.end('c')
    >>> ts.begin('c')
    >>> time.sleep(0.3)
    >>> ts.end('b') # will also end 'c'.
    >>> ts.begin('d')
    >>> ts.begin('e')
    >>> time.sleep(0.1)
    >>> ts.end_all()    # will end everything.
    >>> print(ts)
    Timings (in seconds):
        1.0 a
            0.8 b
                0.6/2 c
            0.1 d
                0.1 e
    <BLANKLINE>

    One can also use as a context manager:
    >>> ts = Timings()
    >>> with ts( 'foo'):
    ...     time.sleep(1)
    ...     with ts( 'bar'):
    ...         time.sleep(1)
    >>> print( ts)
    Timings (in seconds):
        2.0 foo
            1.0 bar
    <BLANKLINE>

    Must specify name, otherwise we assert-fail.
    >>> with ts:
    ...     pass
    Traceback (most recent call last):
    AssertionError: Must specify <name> etc when using "with ...".
    '''
    def __init__( self, name='', active=True):
        '''
        If <active> is False, returned instance does nothing.
        '''
        self.active = active
        self.root_item = TimingsItem( name)
        self.nest = [ self.root_item]
        self.nest[0].begin( time.time())
        self.name_max_len = 0
        self.call_enter_state = None
        self.call_enter_stack = []

    def begin( self, name=None, text=None, level=0, t=None):
        '''
        Starts a new timing item as child of most recent in-progress timing
        item.

        name:
            Used in final statistics. If None, we use jlib.place().
        text:
            If not None, this is output here with jlib.log().
        level:
            Verbosity. Added to g_verbose.
        '''
        if not self.active:
            return
        if t is None:
            t = time.time()
        if name is None:
            name = place(2)
        self.name_max_len = max( self.name_max_len, len(name))
        leaf = self.nest[-1].children.setdefault( name, TimingsItem( name))
        self.nest.append( leaf)
        leaf.begin( t)
        if text:
            log( text, nv=0)

    def end( self, name=None, t=None):
        '''
        Repeatedly ends the most recent item until we have ended item called
        <name>. Ends just the most recent item if name is None.
        '''
        if not self.active:
            return
        if t is None:
            t = time.time()
        if name is None:
            name = self.nest[-1].name
        while self.nest:
            leaf = self.nest.pop()
            leaf.end( t)
            if leaf.name == name:
                break
        else:
            if name is not None:
                log( f'*** Warning: cannot end timing item called {name} because not found.')

    def end_all( self):
        self.end( self.nest[0].name)

    def mid( self, name=None):
        '''
        Ends current leaf item and starts a new item called <name>. Useful to
        define multiple timing blocks at same level.
        '''
        if not self.active:
            return
        t = time.time()
        if len( self.nest) > 1:
            self.end( self.nest[-1].name, t)
        self.begin( name, t=t)

    def __enter__( self):
        if not self.active:
            return
        assert self.call_enter_state, 'Must specify <name> etc when using "with ...".'
        name, text, level = self.call_enter_state
        self.begin( name, text, level)
        self.call_enter_state = None
        self.call_enter_stack.append( name)

    def __exit__( self, type, value, traceback):
        if not self.active:
            return
        assert not self.call_enter_state, f'self.call_enter_state is not false: {self.call_enter_state}'
        name = self.call_enter_stack.pop()
        self.end( name)

    def __call__( self, name=None, text=None, level=0):
        '''
        Allow scoped timing.
        '''
        if not self.active:
            return self
        assert not self.call_enter_state, f'self.call_enter_state is not false: {self.call_enter_state}'
        self.call_enter_state = ( name, text, level)
        return self

    def text( self, item, depth=0, precision=1):
        '''
        Returns text showing hierachical timing information.
        '''
        if not self.active:
            return ''
        if item is self.root_item and not item.name:
            # Don't show top-level.
            ret = ''
        else:
            tt = '  None' if item.t is None else f'{item.t:6.{precision}f}'
            n = f'/{item.n}' if item.n >= 2 else ''
            ret = f'{" " * 4 * depth} {tt}{n} {item.name}\n'
            depth += 1
        for _, timing2 in item.children.items():
            ret += self.text( timing2, depth, precision)
        return ret

    def __str__( self):
        ret = 'Timings (in seconds):\n'
        ret += self.text( self.root_item, 0)
        return ret


def strpbrk( text, substrings):
    '''
    Finds first occurrence of any item in <substrings> in <text>.

    Returns (pos, substring) or (len(text), None) if not found.
    '''
    ret_pos = len( text)
    ret_substring = None
    for substring in substrings:
        pos = text.find( substring)
        if pos >= 0 and pos < ret_pos:
            ret_pos = pos
            ret_substring = substring
    return ret_pos, ret_substring


def split_first_of( text, substrings):
    '''
    Returns (pre, post), where <pre> doesn't contain any item in <substrings>
    and <post> is empty or starts with an item in <substrings>.
    '''
    pos, _ = strpbrk( text, substrings)
    return text[ :pos], text[ pos:]



log_levels_add_env()


def force_line_buffering():
    '''
    Ensure sys.stdout and sys.stderr are line-buffered. E.g. makes things work
    better if output is piped to a file via 'tee'.

    Returns original out,err streams.
    '''
    stdout0 = sys.stdout
    stderr0 = sys.stderr
    sys.stdout = os.fdopen( sys.stdout.fileno(), 'w', 1)
    sys.stderr = os.fdopen( sys.stderr.fileno(), 'w', 1)
    return stdout0, stderr0


def exception_info(
        exception_or_traceback=None,
        limit=None,
        file=None,
        chain=True,
        outer=True,
        _filelinefn=True,
        ):
    '''
    Shows an exception and/or backtrace.

    Alternative to traceback.* functions that print/return
    information about exceptions and backtraces, such as:

        traceback.format_exc()
        traceback.format_exception()
        traceback.print_exc()
        traceback.print_exception()

    Install as system default with:
        sys.excepthook = lambda type_, exception, traceback: jlib.exception_info( exception)

    Returns None, or the generated text if <file> is 'return'.

    Args:
        exception_or_traceback:
            None, a BaseException, a types.TracebackType or a list of
            inspect.FrameInfo's. If None we use current exception from
            sys.exc_info() if set, otherwise the current backtrace from
            inspect.stack().
        limit:
            As in traceback.* functions: None to show all frames, positive to
            show last <limit> frames, negative to exclude outermost -limit
            frames.
        file:
            As in traceback.* functions: file-like object to which we write
            output, or sys.stderr if None. Special value 'return' makes us
            return our output as a string.
        chain:
            As in traceback.* functions: if true (the default) we show chained
            exceptions as described in PEP-3134. Special value 'because'
            reverses the usual ordering, showing higher-level exceptions first
            and joining with 'Because:' text.
        outer:
            If true (the default) we also show an exception's outer frames
            above the catch block (see next section for details). We use
            outer=false internally for chained exceptions to avoid duplication.
        _filelinefn:
            Internal only; makes us omit file:line: information to allow simple
            doctest comparison with expected output.

    Differences from traceback.* functions:

        Frames are displayed as one line in the form:
            <file>:<line>:<function>: <text>

        Filenames are displayed as relative to the current directory if
        applicable.

        Inclusion of outer frames:
            Unlike traceback.* functions, stack traces for exceptions include
            outer stack frames above the point at which an exception was caught
            - i.e. frames from the top-level <module> or thread creation to the
            catch block. [Search for 'sys.exc_info backtrace incomplete' for
            more details.]

            We separate the two parts of the backtrace using a marker line
            '^except raise:' where '^except' points upwards to the frame that
            caught the exception and 'raise:' refers downwards to the frame
            that raised the exception.

            So the backtrace for an exception looks like this:

                <file>:<line>:<fn>: <text>  [in root module.]
                ...                         [... other frames]
                <file>:<line>:<fn>: <text>  [in except: block where exception was caught.]
                ^except raise:              [marker line]
                <file>:<line>:<fn>: <text>  [in try: block.]
                ...                         [... other frames]
                <file>:<line>:<fn>: <text>  [where the exception was raised.]

    Examples:

        In these examples we use file=sys.stdout so we can check the output
        with doctest, and set _filelinefn=0 so that the output can be matched
        easily. We also use +ELLIPSIS and '...' to match arbitrary outer frames
        from the doctest code itself.

        Basic handling of an exception:

            >>> def c():
            ...     raise Exception( 'c() failed')
            >>> def b():
            ...     try:
            ...         c()
            ...     except Exception as e:
            ...         exception_info( e, file=sys.stdout, _filelinefn=0)
            >>> def a():
            ...     b()

            >>> a() # doctest: +REPORT_UDIFF +ELLIPSIS
            Traceback (most recent call last):
                ...
                a(): b()
                b(): exception_info( e, file=sys.stdout, _filelinefn=0)
                ^except raise:
                b(): c()
                c(): raise Exception( 'c() failed')
            Exception: c() failed

        Handling of chained exceptions:

            >>> def e():
            ...     raise Exception( 'e(): deliberate error')
            >>> def d():
            ...     e()
            >>> def c():
            ...     try:
            ...         d()
            ...     except Exception as e:
            ...         raise Exception( 'c: d() failed') from e
            >>> def b():
            ...     try:
            ...         c()
            ...     except Exception as e:
            ...         exception_info( file=sys.stdout, chain=g_chain, _filelinefn=0)
            >>> def a():
            ...     b()

            With chain=True (the default), we output low-level exceptions
            first, matching the behaviour of traceback.* functions:

                >>> g_chain = True
                >>> a() # doctest: +REPORT_UDIFF +ELLIPSIS
                Traceback (most recent call last):
                    c(): d()
                    d(): e()
                    e(): raise Exception( 'e(): deliberate error')
                Exception: e(): deliberate error
                <BLANKLINE>
                The above exception was the direct cause of the following exception:
                Traceback (most recent call last):
                    ...
                    <module>(): a() # doctest: +REPORT_UDIFF +ELLIPSIS
                    a(): b()
                    b(): exception_info( file=sys.stdout, chain=g_chain, _filelinefn=0)
                    ^except raise:
                    b(): c()
                    c(): raise Exception( 'c: d() failed') from e
                Exception: c: d() failed

            With chain='because', we output high-level exceptions first:
                >>> g_chain = 'because'
                >>> a() # doctest: +REPORT_UDIFF +ELLIPSIS
                Traceback (most recent call last):
                    ...
                    <module>(): a() # doctest: +REPORT_UDIFF +ELLIPSIS
                    a(): b()
                    b(): exception_info( file=sys.stdout, chain=g_chain, _filelinefn=0)
                    ^except raise:
                    b(): c()
                    c(): raise Exception( 'c: d() failed') from e
                Exception: c: d() failed
                <BLANKLINE>
                Because:
                Traceback (most recent call last):
                    c(): d()
                    d(): e()
                    e(): raise Exception( 'e(): deliberate error')
                Exception: e(): deliberate error

        Show current backtrace by passing exception_or_traceback=None:
            >>> def c():
            ...     exception_info( None, file=sys.stdout, _filelinefn=0)
            >>> def b():
            ...     return c()
            >>> def a():
            ...     return b()

            >>> a() # doctest: +REPORT_UDIFF +ELLIPSIS
            Traceback (most recent call last):
                ...
                <module>(): a() # doctest: +REPORT_UDIFF +ELLIPSIS
                a(): return b()
                b(): return c()
                c(): exception_info( None, file=sys.stdout, _filelinefn=0)

        Show an exception's .__traceback__ backtrace:
            >>> def c():
            ...     raise Exception( 'foo') # raise
            >>> def b():
            ...     return c()  # call c
            >>> def a():
            ...     try:
            ...         b() # call b
            ...     except Exception as e:
            ...         exception_info( e.__traceback__, file=sys.stdout, _filelinefn=0)

            >>> a() # doctest: +REPORT_UDIFF +ELLIPSIS
            Traceback (most recent call last):
                ...
                a(): b() # call b
                b(): return c()  # call c
                c(): raise Exception( 'foo') # raise
    '''
    # Set exactly one of <exception> and <tb>.
    #
    if isinstance( exception_or_traceback, (types.TracebackType, inspect.FrameInfo)):
        # Simple backtrace, no Exception information.
        exception = None
        tb = exception_or_traceback
    elif isinstance( exception_or_traceback, BaseException):
        exception = exception_or_traceback
        tb = None
    elif exception_or_traceback is None:
        # Show exception if available, else backtrace.
        _, exception, tb = sys.exc_info()
        tb = None if exception else inspect.stack()[1:]
    else:
        assert 0, f'Unrecognised exception_or_traceback type: {type(exception_or_traceback)}'

    if file == 'return':
        out = io.StringIO()
    else:
        out = file if file else sys.stderr

    def do_chain( exception):
        exception_info( exception, limit, out, chain, outer=False, _filelinefn=_filelinefn)

    if exception and chain and chain != 'because':
        # Output current exception first.
        if exception.__cause__:
            do_chain( exception.__cause__)
            out.write( '\nThe above exception was the direct cause of the following exception:\n')
        elif exception.__context__:
            do_chain( exception.__context__)
            out.write( '\nDuring handling of the above exception, another exception occurred:\n')

    cwd = os.getcwd() + os.sep

    def output_frames( frames, reverse, limit):
        if reverse:
            assert isinstance( frames, list)
            frames = reversed( frames)
        if limit is not None:
            frames = list( frames)
            frames = frames[ -limit:]
        for frame in frames:
            f, filename, line, fnname, text, index = frame
            text = text[0].strip() if text else ''
            if filename.startswith( cwd):
                filename = filename[ len(cwd):]
            if filename.startswith( f'.{os.sep}'):
                filename = filename[ 2:]
            if _filelinefn:
                out.write( f'    {filename}:{line}:{fnname}(): {text}\n')
            else:
                out.write( f'    {fnname}(): {text}\n')

    out.write( 'Traceback (most recent call last):\n')
    if exception:
        tb = exception.__traceback__
        assert tb
        if outer:
            output_frames( inspect.getouterframes( tb.tb_frame), reverse=True, limit=limit)
            out.write( '    ^except raise:\n')
        output_frames( inspect.getinnerframes( tb), reverse=False, limit=None)
    else:
        if not isinstance( tb, list):
            inner = inspect.getinnerframes(tb)
            outer = inspect.getouterframes(tb.tb_frame)
            tb = outer + inner
            tb.reverse()
        output_frames( tb, reverse=True, limit=limit)

    if exception:
        lines = traceback.format_exception_only( type(exception), exception)
        for line in lines:
            out.write( line)

    if exception and chain == 'because':
        # Output current exception afterwards.
        if exception.__cause__:
            out.write( '\nBecause:\n')
            do_chain( exception.__cause__)
        elif exception.__context__:
            out.write( '\nBecause error occurred handling this exception:\n')
            do_chain( exception.__context__)

    if file == 'return':
        return out.getvalue()


def number_sep( s):
    '''
    Simple number formatter, adds commas in-between thousands. <s> can
    be a number or a string. Returns a string.

    >>> number_sep(1)
    '1'
    >>> number_sep(12)
    '12'
    >>> number_sep(123)
    '123'
    >>> number_sep(1234)
    '1,234'
    >>> number_sep(12345)
    '12,345'
    >>> number_sep(123456)
    '123,456'
    >>> number_sep(1234567)
    '1,234,567'
    '''
    if not isinstance( s, str):
        s = str( s)
    c = s.find( '.')
    if c==-1:   c = len(s)
    end = s.find('e')
    if end == -1:   end = s.find('E')
    if end == -1:   end = len(s)
    ret = ''
    for i in range( end):
        ret += s[i]
        if i<c-1 and (c-i-1)%3==0:
            ret += ','
        elif i>c and i<end-1 and (i-c)%3==0:
            ret += ','
    ret += s[end:]
    return ret


class Stream:
    '''
    Base layering abstraction for streams - abstraction for things like
    sys.stdout to allow prefixing of all output, e.g. with a timestamp.
    '''
    def __init__( self, stream):
        self.stream = stream
    def write( self, text):
        self.stream.write( text)

class StreamPrefix:
    '''
    Prefixes output with a prefix, which can be a string or a callable that
    takes no parameters and return a string.
    '''
    def __init__( self, stream, prefix):
        if callable(stream):
            self.stream_write = stream
            self.stream_flush = lambda: None
        else:
            self.stream_write = stream.write
            self.stream_flush = stream.flush
        self.at_start = True
        if callable(prefix):
            self.prefix = prefix
        else:
            self.prefix = lambda : prefix

    def write( self, text):
        if self.at_start:
            text = self.prefix() + text
            self.at_start = False
        append_newline = False
        if text.endswith( '\n'):
            text = text[:-1]
            self.at_start = True
            append_newline = True
        text = text.replace( '\n', '\n%s' % self.prefix())
        if append_newline:
            text += '\n'
        self.stream_write( text)

    def flush( self):
        self.stream_flush()


def time_duration( seconds, verbose=False, s_format='%i'):
    '''
    Returns string expressing an interval.

    seconds:
        The duration in seconds
    verbose:
        If true, return like '4 days 1 hour 2 mins 23 secs', otherwise as
        '4d3h2m23s'.
    s_format:
        If specified, use as printf-style format string for seconds.

    >>> time_duration( 303333)
    '3d12h15m33s'

    >>> time_duration( 303333.33, s_format='%.1f')
    '3d12h15m33.3s'

    >>> time_duration( 303333, verbose=True)
    '3 days 12 hours 15 mins 33 secs'

    >>> time_duration( 303333.33, verbose=True, s_format='%.1f')
    '3 days 12 hours 15 mins 33.3 secs'

    >>> time_duration( 0)
    '0s'

    >>> time_duration( 0, verbose=True)
    '0 sec'
    '''
    x = abs(seconds)
    ret = ''
    i = 0
    for div, text in [
            ( 60, 'sec'),
            ( 60, 'min'),
            ( 24, 'hour'),
            ( None, 'day'),
            ]:
        force = ( x == 0 and i == 0)
        if div:
            remainder = x % div
            x = int( x/div)
        else:
            remainder = x
        if not verbose:
            text = text[0]
        if remainder or force:
            if verbose and remainder > 1:
                # plural.
                text += 's'
            if verbose:
                text = ' %s ' % text
            if i == 0:
                remainder = s_format % remainder
            ret = '%s%s%s' % ( remainder, text, ret)
        i += 1
    ret = ret.strip()
    if ret == '':
        ret = '0s'
    if seconds < 0:
        ret = '-%s' % ret
    return ret


def date_time( t=None):
    if t is None:
        t = time.time()
    return time.strftime( "%F-%T", time.gmtime( t))

def stream_prefix_time( stream):
    '''
    Returns StreamPrefix that prefixes lines with time and elapsed time.
    '''
    t_start = time.time()
    def prefix_time():
        return '%s (+%s): ' % (
                time.strftime( '%T'),
                time_duration( time.time() - t_start, s_format='0.1f'),
                )
    return StreamPrefix( stream, prefix_time)

def stdout_prefix_time():
    '''
    Changes sys.stdout to prefix time and elapsed time; returns original
    sys.stdout.
    '''
    ret = sys.stdout
    sys.stdout = stream_prefix_time( sys.stdout)
    return ret


def make_out_callable( out):
    '''
    Returns a stream-like object with a .write() method that writes to <out>.
    out:
        Where output is sent.
        If None, output is lost.
        Otherwise if an integer, we do: os.write( out, text)
        Otherwise if callable, we do: out( text)
        Otherwise we assume <out> is python stream or similar, and do: out.write(text)
    '''
    class Ret:
        def write( self, text):
            pass
        def flush( self):
            pass
    ret = Ret()
    if out == log:
        # A hack to avoid expanding '{...}' in text, if caller
        # does: jlib.system(..., out=jlib.log, ...).
        out = lambda text: log(text, nv=False)
    if out is None:
        ret.write = lambda text: None
    elif isinstance( out, int):
        ret.write = lambda text: os.write( out, text)
    elif callable( out):
        ret.write = out
    else:
        ret.write = lambda text: out.write( text)
    return ret

def _env_extra_text( env_extra):
    ret = ''
    if env_extra:
        for n, v in env_extra.items():
            assert isinstance( n, str), f'env_extra has non-string name {n!r}: {env_extra!r}'
            assert isinstance( v, str), f'env_extra name={n!r} has non-string value {v!r}: {env_extra!r}'
            ret += f'{n}={shlex.quote(v)} '
    return ret

def system(
        command,
        verbose=None,
        raise_errors=True,
        out=sys.stdout,
        prefix=None,
        shell=True,
        encoding='utf8',
        errors='replace',
        executable=None,
        caller=1,
        bufsize=-1,
        env_extra=None,
        ):
    '''
    Runs a command like os.system() or subprocess.*, but with more flexibility.

    We give control over where the command's output is sent, whether to return
    the output and/or exit code, and whether to raise an exception if the
    command fails.

    Args:

        command:
            The command to run.
        verbose:
            If true, we write information about the command that was run, and
            its result, to jlib.log().
        raise_errors:
            If true, we raise an exception if the command fails, otherwise we
            return the failing error code or zero.
        out:
            Where to send output from child process.

            <out> is <o> or (o, prefix) or list of such items. Each <o> is
            matched as follows:

                None: child process inherits this process's stdout and
                stderr. (Must be the only item, and <prefix> is not supported.)

                subprocess.DEVNULL: child process's output is lost. (Must be
                the only item, and <prefix> is not supported.)

                'return': we store the output and include it in our return
                value or exception. Can only be specified once.

                'log': we write to jlib.log() using our caller's stack
                frame. Can only be specified once.

                An integer: we do: os.write(o, text)

                Is callable: we do: o(text)

                Otherwise we assume <o> is python stream or similar, and do:
                o.write(text)

            If <prefix> is specified, it is applied to each line in the output
            before being sent to <o>.
        prefix:
            Default prefix for all items in <out>.
        shell:
            Passed to underlying subprocess.Popen() call.
        encoding:
            Sepecify the encoding used to translate the command's output to
            characters. If None we send bytes to items in <out>.
        errors:
            How to handle encoding errors; see docs for codecs module
            for details. Defaults to 'replace' so we never raise a
            UnicodeDecodeError.
        executable=None:
            .
        caller:
            The number of frames to look up stack when call jlib.log() (used
            for out='log' and verbose).
        bufsize:
            As subprocess.Popen()'s bufsize arg, sets buffer size when creating
            stdout, stderr and stdin pipes. Use 0 for unbuffered, e.g. to see
            login/password prompts that don't end with a newline. Default -1
            means io.DEFAULT_BUFFER_SIZE. +1 Line-buffered does not work because
            we read raw bytes and decode ourselves into string.
        env_extra:
            If not None, a dict with extra items that are added to the
            environment passed to the child process.

    Returns:
        raise_errors:
            true:
                If the command failed, we raise an exception; if <out> contains
                'return' the exception text includes the output.

                Else if <out> contains 'return' we return the text output from the
                command.

                Else we return None.
            false:
                If <out> contains 'return', we return (e, text) where <e> is the
                command's exit code and <text> is the output from the command.

                Else we return <e>, the command's return code.

                In the above, <e> is the subprocess-style returncode - the exit
                code, or -N if killed by signal N.

    >>> print(system('echo hello a', prefix='foo:', out='return'))
    foo:hello a
    foo:

    >>> system('echo hello b', prefix='foo:', out='return', raise_errors=False)
    (0, 'foo:hello b\\nfoo:')

    >>> system('echo hello c && false', prefix='foo:', out='return', env_extra=dict(FOO='bar qwerty'))
    Traceback (most recent call last):
    Exception: Command failed: FOO='bar qwerty' echo hello c && false
    Output was:
    foo:hello c
    foo:
    <BLANKLINE>
    '''
    out_pipe = 0
    out_none = 0
    out_devnull = 0
    out_return = None
    out_log = 0

    outs = out if isinstance(out, list) else [out]
    for i, o in enumerate(outs):
        if o is None:
            out_none += 1
        elif o == subprocess.DEVNULL:
            out_devnull += 1
        else:
            out_pipe += 1
            o_prefix = prefix
            if isinstance(o, tuple) and len(o) == 2:
                o, o_prefix = o
                assert o not in (None, subprocess.DEVNULL), f'out[]={o} does not make sense with a prefix ({o_prefix})'
            assert not isinstance(o, (tuple, list))
            if o == 'return':
                assert not out_return, f'"return" specified twice does not make sense'
                out_return = io.StringIO()
                outs[i] = out_return.write
            elif o == 'log':
                assert not out_log, f'"log" specified twice does not make sense'
                out_log += 1
                out_frame_record = inspect.stack()[caller]
                outs[i] = lambda text: log( text, caller=out_frame_record, nv=False, raw=True)
            elif isinstance(o, int):
                outs[i] = lambda text: os.write( o, text)
            elif callable(o):
                outs[i] = o
            else:
                assert hasattr(o, 'write') and callable(o.write), (
                        f'Do not understand o={o}, must be one of:'
                            ' None, subprocess.DEVNULL, "return", "log", <int>,'
                            ' or support o() or o.write().'
                            )
                outs[i] = o.write
            if o_prefix:
                outs[i] = StreamPrefix( outs[i], o_prefix).write

    if out_pipe:
        stdout = subprocess.PIPE
        stderr = subprocess.STDOUT
    elif out_none == len(outs):
        stdout = None
        stderr = None
    elif out_devnull == len(outs):
        stdout = subprocess.DEVNULL
        stderr = subprocess.DEVNULL
    else:
        assert 0, f'Inconsistent out: {out}'

    if verbose:
        log(f'running: {_env_extra_text(env_extra)}{command}', nv=0, caller=caller+1)

    env = None
    if env_extra:
        env = os.environ.copy()
        env.update(env_extra)

    child = subprocess.Popen(
            command,
            shell=shell,
            stdin=None,
            stdout=stdout,
            stderr=stderr,
            close_fds=True,
            executable=executable,
            bufsize=bufsize,
            env=env
            )

    if out_pipe:
        decoder = None
        if encoding:
            # subprocess's universal_newlines and codec.streamreader seem to
            # always use buffering even with bufsize=0, so they don't reliably
            # display prompts or other text that doesn't end with a newline.
            #
            # So we create our own incremental decode, which seems to work
            # better.
            #
            decoder = codecs.getincrementaldecoder(encoding)(errors)
        while 1:
            # os.read() seems to be better for us than child.stdout.read()
            # because it returns a short read if data is not available. Where
            # as child.stdout.read() appears to be more willing to wait for
            # data until the requested number of bytes have been received.
            #
            # Also, os.read() does the right thing if the sender has made
            # multipe calls to write() - it returns all available data, not
            # just from the first unread write() call.
            #
            output = os.read( child.stdout.fileno(), 10000)
            if decoder:
                final = not output
                output = decoder.decode(output, final)
            for o in outs:
                o(output)
            if not output:
                break

    e = child.wait()

    if out_log:
        global _log_text_line_start
        if not _log_text_line_start:
            # Terminate last incomplete line of log outputs.
            sys.stdout.write('\n')
            _log_text_line_start = True
    if verbose:
        log(f'[returned e={e}]', nv=0, caller=caller+1)

    if out_return:
        out_return = out_return.getvalue()

    if raise_errors:
        if e:
            message = f'Command failed: {_env_extra_text(env_extra)}{command}'
            if out_return is not None:
                if not out_return.endswith('\n'):
                    out_return += '\n'
                raise Exception(
                        message + '\n'
                        + 'Output was:\n'
                        + out_return
                        )
            else:
                raise Exception( message)
        elif out_return is not None:
            return out_return
        else:
            return

    if out_return is not None:
        return e, out_return
    else:
        return e


def system_rusage(
        command,
        verbose=None,
        raise_errors=True,
        out=sys.stdout,
        prefix=None,
        rusage=False,
        shell=True,
        encoding='utf8',
        errors='replace',
        executable=None,
        caller=1,
        bufsize=-1,
        env_extra=None,
        ):
    '''
    Old code that gets timing info; probably doesn't work.
    '''
    command2 = ''
    command2 += '/usr/bin/time -o ubt-out -f "D=%D E=%D F=%F I=%I K=%K M=%M O=%O P=%P R=%r S=%S U=%U W=%W X=%X Z=%Z c=%c e=%e k=%k p=%p r=%r s=%s t=%t w=%w x=%x C=%C"'
    command2 += ' '
    command2 += command

    e = system(
            command2,
            out,
            shell,
            encoding,
            errors,
            executable=executable,
            )
    if e:
        raise Exception('/usr/bin/time failed')
    with open('ubt-out') as f:
        rusage_text = f.read()
    #print 'have read rusage output: %r' % rusage_text
    if rusage_text.startswith( 'Command '):
        # Annoyingly, /usr/bin/time appears to write 'Command
        # exited with ...' or 'Command terminated by ...' to the
        # output file before the rusage info if command doesn't
        # exit 0.
        nl = rusage_text.find('\n')
        rusage_text = rusage_text[ nl+1:]
    return rusage_text


def get_gitfiles( directory, submodules=False):
    '''
    Returns list of all files known to git in <directory>; <directory> must be
    somewhere within a git checkout.

    Returned names are all relative to <directory>.

    If <directory>.git exists we use git-ls-files and write list of files to
    <directory>/jtest-git-files.

    Otherwise we require that <directory>/jtest-git-files already exists.
    '''
    def is_within_git_checkout( d):
        while 1:
            #log( '{d=}')
            if not d:
                break
            if os.path.isdir( f'{d}/.git'):
                return True
            d = os.path.dirname( d)

    if is_within_git_checkout( directory):
        command = 'cd ' + directory + ' && git ls-files'
        if submodules:
            command += ' --recurse-submodules'
        command += ' > jtest-git-files'
        system( command, verbose=True)

    with open( '%s/jtest-git-files' % directory, 'r') as f:
        text = f.read()
    ret = text.strip().split( '\n')
    return ret

def get_git_id_raw( directory):
    if not os.path.isdir( '%s/.git' % directory):
        return
    text = system(
            f'cd {directory} && (PAGER= git show --pretty=oneline|head -n 1 && git diff)',
            out='return',
            )
    return text

def get_git_id( directory, allow_none=False):
    '''
    Returns text where first line is '<git-sha> <commit summary>' and remaining
    lines contain output from 'git diff' in <directory>.

    directory:
        Root of git checkout.
    allow_none:
        If true, we return None if <directory> is not a git checkout and
        jtest-git-id file does not exist.
    '''
    filename = f'{directory}/jtest-git-id'
    text = get_git_id_raw( directory)
    if text:
        with open( filename, 'w') as f:
            f.write( text)
    elif os.path.isfile( filename):
        with open( filename) as f:
            text = f.read()
    else:
        if not allow_none:
            raise Exception( f'Not in git checkout, and no file called: {filename}.')
        text = None
    return text

class Args:
    '''
    Iterates over argv items.
    '''
    def __init__( self, argv):
        self.items = iter( argv)
    def next( self):
        if sys.version_info[0] == 3:
            return next( self.items)
        else:
            return self.items.next()
    def next_or_none( self):
        try:
            return self.next()
        except StopIteration:
            return None

def update_file( text, filename, return_different=False):
    '''
    Writes <text> to <filename>. Does nothing if contents of <filename> are
    already <text>.

    If <return_different> is true, we return existing contents if <filename>
    already exists and differs from <text>.
    '''
    try:
        with open( filename) as f:
            text0 = f.read()
    except OSError:
        text0 = None
    if text != text0:
        if return_different and text0 is not None:
            return text
        log( 'Updating:  ' + filename)
        # Write to temp file and rename, to ensure we are atomic.
        filename_temp = f'{filename}-jlib-temp'
        with open( filename_temp, 'w') as f:
            f.write( text)
        rename( filename_temp, filename)


def find_in_paths( name, paths=None):
    '''
    Looks for <name> in paths and returns complete path. paths is list/tuple or
    colon-separated string; if None we use $PATH. If `name` contains `/`, we
    return `name` itself if it is a file, regardless of $PATH.
    '''
    if '/' in name:
        return name if os.path.isfile( name) else None
    if paths is None:
        paths = os.environ.get( 'PATH', '')
    if isinstance( paths, str):
        paths = paths.split( ':')
    for path in paths:
        p = f'{path}/{name}'
        if os.path.isfile( p):
            return p


def fs_find_in_paths( name, paths=None, verbose=False):
    '''
    Looks for `name` in paths and returns complete path. `paths` is list/tuple
    or colon-separated string; if `None` we use `$PATH`.
    '''
    if paths is None:
        paths = os.environ.get( 'PATH', '')
    if isinstance( paths, str):
        paths = paths.split( os.pathsep)
    for path in paths:
        p = os.path.join( path, name)
        if os.path.isfile( p):
            if verbose:
                log( 'Returning: {p}')
            return p
        if verbose:
            log( 'Does not exist or is not file: {p}')


def mtime( filename, default=0):
    '''
    Returns mtime of file, or <default> if error - e.g. doesn't exist.
    '''
    try:
        return os.path.getmtime( filename)
    except OSError:
        return default


def filesize( filename, default=0):
    try:
        return os.path.getsize( filename)
    except OSError:
        return default


def get_filenames( paths):
    '''
    Yields each file in <paths>, walking any directories.

    If <paths> is a tuple (paths2, filter_) and <filter_> is callable, we yield
    all files in <paths2> for which filter_(path2) returns true.
    '''
    filter_ = lambda path: True
    if isinstance( paths, tuple) and len( paths) == 2 and callable( paths[1]):
        paths, filter_ = paths
    if isinstance( paths, str):
        paths = (paths,)
    for name in paths:
        if os.path.isdir( name):
            for dirpath, dirnames, filenames in os.walk( name):
                for filename in filenames:
                    path = os.path.join( dirpath, filename)
                    if filter_( path):
                        yield path
        else:
            if filter_( name):
                yield name

def remove( path, backup=False):
    '''
    Removes file or directory, without raising exception if it doesn't exist.

    path:
        The path to remove.
    backup:
        If true, we rename any existing file/directory called <path> to
        <path>-<datetime>.

    We assert-fail if the path still exists when we return, in case of
    permission problems etc.
    '''
    if backup and os.path.exists( path):
        datetime = date_time()
        if platform.system() == 'Windows' or platform.system().startswith( 'CYGWIN'):
            # os.rename() fails if destination contains colons, with:
            #   [WinError87] The parameter is incorrect ...
            datetime = datetime.replace( ':', '')
        p = f'{path}-{datetime}'
        log( 'Moving out of way: {path} => {p}')
        os.rename( path, p)
    try:
        os.remove( path)
    except Exception:
        pass
    shutil.rmtree( path, ignore_errors=1)
    assert not os.path.exists( path)

def remove_dir_contents( path):
    '''
    Removes all items in directory <path>; does not remove <path> itself.
    '''
    for leaf in os.listdir( path):
        path2 = os.path.join( path, leaf)
        remove(path2)

def ensure_empty_dir( path):
    os.makedirs( path, exist_ok=True)
    remove_dir_contents( path)

def rename(src, dest):
    '''
    Renames <src> to <dest>. If we get an error, we try to remove <dest>
    expicitly and then retry; this is to make things work on Windows.
    '''
    try:
        os.rename(src, dest)
    except Exception:
        os.remove(dest)
        os.rename(src, dest)

def copy(src, dest, verbose=False):
    '''
    Wrapper for shutil.copy() that also ensures parent of <dest> exists and
    optionally calls jlib.log() with diagnostic.
    '''
    if verbose:
        log('Copying {src} to {dest}')
    dirname = os.path.dirname(dest)
    if dirname:
        os.makedirs( dirname, exist_ok=True)
    shutil.copy2( src, dest)


def untar(path, mode='r:gz', prefix=None):
    '''
    Extracts tar file.

    We fail if items in tar file have different top-level directory names, or
    if tar file's top-level directory name already exists locally.

    path:
        The tar file.
    mode:
        As tarfile.open().
    prefix:
        If not None, we fail if tar file's top-level directory name is not
        <prefix>.

    Returns the directory name (which will be <prefix> if not None).
    '''
    with tarfile.open( path, mode) as t:
        items = t.getnames()
        assert items
        item = items[0]
        assert not item.startswith('.')
        s = item.find('/')
        if s == -1:
            prefix_actual = item + '/'
        else:
            prefix_actual = item[:s+1]
        if prefix:
            assert prefix == prefix_actual, f'prefix={prefix} prefix_actual={prefix_actual}'
        for item in items[1:]:
            assert item.startswith( prefix_actual), f'prefix_actual={prefix_actual!r} != item={item!r}'
        assert not os.path.exists( prefix_actual)
        t.extractall()
    return prefix_actual


# Things for figuring out whether files need updating, using mtimes.
#
def newest( names):
    '''
    Returns mtime of newest file in <filenames>. Returns 0 if no file exists.
    '''
    assert isinstance( names, (list, tuple))
    assert names
    ret_t = 0
    ret_name = None
    for filename in get_filenames( names):
        if filename.endswith('.pyc'):
            continue
        t = mtime( filename)
        if t > ret_t:
            ret_t = t
            ret_name = filename
    return ret_t, ret_name

def oldest( names):
    '''
    Returns mtime of oldest file in <filenames> or 0 if no file exists.
    '''
    assert isinstance( names, (list, tuple))
    assert names
    ret_t = None
    ret_name = None
    for filename in get_filenames( names):
        t = mtime( filename)
        if ret_t is None or t < ret_t:
            ret_t = t
            ret_name = filename
    if ret_t is None:
        ret_t = 0
    return ret_t, ret_name

def update_needed( infiles, outfiles):
    '''
    If any file in <infiles> is newer than any file in <outfiles>, returns
    string description. Otherwise returns None.
    '''
    in_tmax, in_tmax_name = newest( infiles)
    out_tmin, out_tmin_name = oldest( outfiles)
    if in_tmax > out_tmin:
        text = f'{in_tmax_name} is newer than {out_tmin_name}'
        return text

def ensure_parent_dir( path):
    parent = os.path.dirname( path)
    if parent:
        os.makedirs( parent, exist_ok=True)

def build(
        infiles,
        outfiles,
        command,
        force_rebuild=False,
        out=None,
        all_reasons=False,
        verbose=True,
        executable=None,
        ):
    '''
    Ensures that <outfiles> are up to date using enhanced makefile-like
    determinism of dependencies.

    Rebuilds <outfiles> by running <command> if we determine that any of them
    are out of date, or if <comand> has changed.

    infiles:
        Names of files that are read by <command>. Can be a single filename. If
        an item is a directory, we expand to all filenames in the directory's
        tree. Can be (files2, filter_) as supported by jlib.get_filenames().
    outfiles:
        Names of files that are written by <command>. Can also be a
        single filename. Can be (files2, filter_) as supported by
        jlib.get_filenames().
    command:
        Command to run. {IN} and {OUT} are replaced by space-separated
        <infiles> and <outfiles> with '/' changed to '\' on Windows.
    force_rebuild:
        If true, we always re-run the command.
    out:
        A callable, passed to jlib.system(). If None, we use jlib.log()
        with our caller's stack record (by passing (out='log', caller=2) to
        jlib.system()).
    all_reasons:
        If true we check all ways for a build being needed, even if we already
        know a build is needed; this only affects the diagnostic that we
        output.
    verbose:
        Passed to jlib.system().

    Returns:
        true if we have run the command, otherwise None.

    We compare mtimes of <infiles> and <outfiles>, and we also detect changes
    to the command itself.

    If any of infiles are newer than any of outfiles, or <command> is
    different to contents of commandfile '<outfile[0]>.cmd, then truncates
    commandfile and runs <command>. If <command> succeeds we writes <command>
    to commandfile.
    '''
    if isinstance( infiles, str):
        infiles = (infiles,)
    if isinstance( outfiles, str):
        outfiles = (outfiles,)

    if out is None:
        out = 'log'

    command_filename = f'{outfiles[0]}.cmd'
    reasons = []

    if not reasons or all_reasons:
        if force_rebuild:
            reasons.append( 'force_rebuild was specified')

    os_name = platform.system()
    os_windows = (os_name == 'Windows' or os_name.startswith('CYGWIN'))
    def files_string(files):
        if isinstance(files, tuple) and len(files) == 2 and callable(files[1]):
            files = files[0],
        ret = ' '.join(files)
        if os_windows:
            # This works on Cygwyn; we might only need '\\' if running in a Cmd
            # window.
            ret = ret.replace('/', '\\\\')
        return ret
    command = command.replace('{IN}', files_string(infiles))
    command = command.replace('{OUT}', files_string(outfiles))

    if not reasons or all_reasons:
        try:
            with open( command_filename) as f:
                command0 = f.read()
        except Exception:
            command0 = None
        if command != command0:
           reasons.append( 'command has changed')

    if not reasons or all_reasons:
        reason = update_needed( infiles, outfiles)
        if reason:
            reasons.append( reason)

    if not reasons:
        log( 'Already up to date: ' + ' '.join(outfiles), caller=2, nv=0)
        return

    log( f'Rebuilding because {", and ".join(reasons)}: {" ".join(outfiles)}',
            caller=2,
            nv=0,
            )

    # Empty <command_filename) while we run the command so that if command
    # fails but still creates target(s), then next time we will know target(s)
    # are not up to date.
    #
    # We rename the command to a temporary file and then rename back again
    # after the command finishes so that its mtime is unchanged if the command
    # has not changed.
    #
    ensure_parent_dir( command_filename)
    command_filename_temp = command_filename + '-'
    remove(command_filename_temp)
    if os.path.exists( command_filename):
        rename(command_filename, command_filename_temp)
    update_file( command, command_filename_temp)

    system( command, out=out, verbose=verbose, executable=executable, caller=2)

    rename( command_filename_temp, command_filename)

    return True


def link_l_flags( sos, ld_origin=None):
    '''
    Returns link flags suitable for linking with each .so in <sos>.

    We return -L flags for each unique parent directory and -l flags for each
    leafname.

    In addition on Linux and OpenBSD we append " -Wl,-rpath='$ORIGIN,-z,origin"
    so that libraries will be searched for next to each other. This can be
    disabled by setting ld_origin to false.
    '''
    dirs = set()
    names = []
    if isinstance( sos, str):
        sos = [sos]
    ret = ''
    for so in sos:
        if not so:
            continue
        dir_ = os.path.dirname( so)
        name = os.path.basename( so)
        assert name.startswith( 'lib'), f'name={name}'
        if name.endswith( '.so'):
            dirs.add( dir_)
            names.append( f'-l {name[3:-3]}')
        elif name.endswith( '.a'):
            names.append( so)
        else:
            assert 0, f'leaf does not end in .so or .a: {so}'
    ret = ''
    # Important to use sorted() here, otherwise ordering from set() is
    # arbitrary causing occasional spurious rebuilds.
    for dir_ in sorted(dirs):
        ret += f' -L {dir_}'
    for name in names:
        ret += f' {name}'
    if ld_origin is None:
        if os.uname()[0] in ( 'Linux', 'OpenBSD'):
            ld_origin = True
    if ld_origin:
        ret += " -Wl,-rpath='$ORIGIN',-z,origin"
    #log('{sos=} {ld_origin=} {ret=}')
    return ret


class ArgResult:
    '''
    Return type for Arg.parse(), providing access via name, string or integer,
    plus iteration. See Arg docs for details.
    '''
    def __init__(self):
        self._attr = dict() # Maps names to values.
        self._dict = dict() # Maps raw names to values.
        self._list = list() # Ordered list of (name, value, ArgResult) tuples.

    # __getattr__() and __getitem__() augment default behaviour by returning
    # from self._attr or self._list as appropriate.

    def __getattr__(self, name):
        if name.startswith('_'):
            return super().__getattr__(name)
        try:
            # .bar returns self._attr['bar'].
            return self._attr[name]
        except KeyError:
            raise AttributeError

    def __getitem__(self, i):
        if isinstance(i, int):
            # [23] returns self._list[23].
            if i < 0:
                i += len(self._list)
            return self._list[i]
        else:
            # ['foo'] returns self._attr['foo'].
            return self._attr[i]

    def _set(self, name, name_raw, value, multi=False):
        if multi:
            self._attr.setdefault(name, []).append(value)
            self._dict.setdefault(name_raw, []).append(value)
        else:
            assert name not in self._attr
            self._attr[name] = value
            self._dict[name_raw] = value

    def __iter__(self):
        return self._list.__iter__()

    @staticmethod
    def _dict_to_text(d):
        names = sorted(d.keys())
        names = [f'{name}={d[name]!r}' for name in names]
        names = ', '.join(names)
        return names

    def _repr_detailed(self):
        a = self._dict_to_text(self._attr)
        d = self._dict_to_text(self._dict)
        l = [str(i) for i in self._list]
        return f'namespace(attr={a} dict={d} list={l})'

    def __repr__(self):
        assert len(self._attr) == len(self._dict)
        a = self._dict_to_text(self._attr)
        return f'namespace({a})'


class Arg:
    '''
    Command-line parser with simple text-based specifications and support for
    multiple sub-commands.

    An Arg is specified by space-separated items in a syntax string such as
    '-flag' or '-f <foo>' or 'foo <foo> <bar>'. These items will match an
    equal number of argv items. Items inside angled brackets such as '<foo>'
    match any argv item that doesn't starting with '-', otherwise matching
    is literal. If the last item is '...' (without quotes), it matches all
    remaining items in argv.

    Command-line parsing is achieved by creating an empty top-level Arg
    instance with <subargs> set to a list of other Arg instances. The resulting
    top-level Arg's .parse() method will try to match an entire command line
    argv with any or all of these subargs, returning an ArgResult instance that
    represents the matched non-literal items.

    Basics:

        A minimal example:

            >>> parser = Arg('', subargs=[Arg('-f <input>'), Arg('-o <output>')])
            >>> result = parser.parse(['-f', 'in.txt'])
            >>> result
            namespace(f=namespace(input='in.txt'), o=None)
            >>> result.f.input
            'in.txt'

        The .parse() method also accepts a string instead of an argv-style
        list. This is intended for testing ony; the string is split into an
        argv-style list using .split() so quotes and escaped spaces etc are not
        handled correctly.

            >>> parser.parse('-f in.txt')
            namespace(f=namespace(input='in.txt'), o=None)

        Results are keyed off the first item in a syntax string, with
        individual items appearing under each <...> name.

        Individual items in a syntax string (in this case 'f', 'input', 'o',
        'output') are converted into Python identifiers by removing any
        inital '-', converting '-' to '_', and removing any non-alphanumeric
        characters. So '-f' is converted to 'f', '--foo-bar' is converted to
        'foo_bar', '<input>' is converted to 'input' etc. It is an error if two
        or more items in <subargs> have the same first name.

        A matching Arg with no <...> items results in True;

            >>> parser = Arg('', subargs=[Arg('-i')])
            >>> parser.parse('-i')
            namespace(i=True)

        There can be zero literal items:

            >>> parser = Arg('', subargs=[Arg('<in> <log>')])
            >>> parser.parse('foo logfile.txt')
            namespace(in=namespace(in='foo', log='logfile.txt'))

        Note how everything is still keyed off the name of the first item,
        '<in>'.

        An Arg can be matched an arbitary number of times by setting <multi> to
        true; unmatched multi items appear as [] rather than None:

            >>> parser = Arg('', subargs=[Arg('-f <input>', multi=1), Arg('-o <output>', multi=1)])
            >>> parser.parse('-f a.txt -f b.txt -f c.txt')
            namespace(f=[namespace(input='a.txt'), namespace(input='b.txt'), namespace(input='c.txt')], o=[])

    Sub commands:

        One can nest Arg's to represent sub-commands such as 'git commit ...',
        'git diff ...' etc.

            >>> parser = Arg('',
            ...         subargs=[
            ...             Arg('-o <file>'),
            ...             Arg('commit', subargs=[Arg('-a'), Arg('-f <file>')]),
            ...             Arg('diff', subargs=[Arg('-f <file>')]),
            ...             ],
            ...         )
            >>> parser.parse('commit -a -f foo', exit_=0)
            namespace(commit=namespace(a=True, f=namespace(file='foo')), diff=None, o=None)

        Allow multiple instances of the same subcommand by setting <multi> to
        true:

            >>> parser = Arg('',
            ...         subargs=[
            ...             Arg('-o <file>'),
            ...             Arg('commit', multi=1, subargs=[Arg('-f <file>')]),
            ...             Arg('diff', subargs=[Arg('-f <file>')]),
            ...             ],
            ...         )
            >>> argv = 'commit -f foo diff -f bar commit -f wibble'
            >>> result = parser.parse(argv, exit_=0)
            >>> result
            namespace(commit=[namespace(f=namespace(file='foo')), namespace(f=namespace(file='wibble'))], diff=namespace(f=namespace(file='bar')), o=None)

        Iterating over <result> gives (name, value, argvalue) tuples in the
        order in which items were found in argv.

        (name, value) are the name and value of the matched item:

            >>> for n, v, av in result:
            ...     print((n, v))
            ('commit', namespace(f=namespace(file='foo')))
            ('diff', namespace(f=namespace(file='bar')))
            ('commit', namespace(f=namespace(file='wibble')))

        <av> is a ArgValue containing the matched item plus, for convenience,
        None items for all the other subarg items:

            >>> for n, v, av in result:
            ...     print(av)
            namespace(commit=namespace(f=namespace(file='foo')), diff=None, o=None)
            namespace(commit=None, diff=namespace(f=namespace(file='bar')), o=None)
            namespace(commit=namespace(f=namespace(file='wibble')), diff=None, o=None)

        This allows simple iteration through matches in the order in which they
        occured in argv:

            >>> for n, v, av in result:
            ...     if av.commit: print(f'found commit={av.commit}')
            ...     elif av.diff: print(f'found diff={av.diff}')
            ...     elif av.o: print(f'found o={av.o}')
            found commit=namespace(f=namespace(file='foo'))
            found diff=namespace(f=namespace(file='bar'))
            found commit=namespace(f=namespace(file='wibble'))

    Consuming all remaining args:

        Match all remaining items in argv by specifying '...' as the last item
        in the syntax string. This gives a list (which may be empty) containing
        all remaining args.

            >>> parser = Arg('',
            ...         subargs=[
            ...             Arg('-o <file>'),
            ...             Arg('-i ...'),
            ...             ],
            ...         )
            >>> parser.parse('-i foo bar abc pqr')
            namespace(i=['foo', 'bar', 'abc', 'pqr'], o=None)
            >>> parser.parse('-i')
            namespace(i=[], o=None)

        If '...' is the only item in the syntax string, it will appear with
        special name 'remaining_':

            >>> parser = Arg('',
            ...         subargs=[
            ...             Arg('-o <file>'),
            ...             Arg('...'),
            ...             ],
            ...         )
            >>> parser.parse('-i foo bar abc pqr')
            namespace(o=None, remaining_=['-i', 'foo', 'bar', 'abc', 'pqr'])
            >>> parser.parse('')
            namespace(o=None, remaining_=[])

    Error messages:

        If we fail to parse the command line, we show information about what
        could have allowed the parse to make more progress. By default we then
        call sys.exit(1); set exit_ to false to avoid this.

            >>> parser = Arg('', subargs=[Arg('<command>'), Arg('-i <in>'), Arg('-o <out>')])
            >>> parser.parse('foo -i', exit_=0)
            Ran out of arguments, expected one of:
                -i <in>
            >>> parser.parse('-i', exit_=0)
            Ran out of arguments, expected one of:
                -i <in>

            >>> parser.parse('-i foo -i bar', exit_=0)
            Failed at argv[2]='-i', only one instance of -i <in> allowed, expected one of:
                <command>  (value must not start with "-")
                -o <out>

        Args can be marked as required:

            >>> parser = Arg('', subargs=[Arg('-i <in>'), Arg('-o <out>', required=1)])
            >>> parser.parse('-i infile', exit_=0)
            Ran out of arguments, expected one of:
                -o <out>  (required)

    Help text:

        Help text is formatted similarly to the argparse module.

        The help_text() method returns help text for a particular Arg,
        consisting of any <help> text passed to the Arg constructor followed by
        recursive syntax and help text for subargs.

        If parsing fails at '-h' or '--help' in argv, we show help text for
        the relevant Arg. '-h' shows brief help, containing just the first
        paragraph of information for each item.

        Help text for the top-level Arg (e.g. if parsing fails at an initial
        '-h' or '--help' in argv) shows help on all args. In particular
        top-level '--help' shows all available help and syntax information.

        When an Arg is constructed, the help text can be specified as
        arbitrarily indented paragraphs with Python triple-quotes; any common
        indentation will be removed.

        After showing help, we default to calling sys.exit(0); pass exit_=0 to
        disable this.

        Top-level help:

            >>> parser = Arg('',
            ...         help="""
            ...             This is the top level help.
            ...             """,
            ...         subargs=[
            ...             Arg('foo', required=1, multi=1, help='Do foo',
            ...                 subargs=[
            ...                     Arg('-f <file>', help='Input file'),
            ...                     Arg('-o <file>', required=1, help='Output file'),
            ...                     ],
            ...                 ),
            ...             Arg('bar <qwerty>', help='Do bar'),
            ...             ],
            ...         )
            >>> parser.parse('-h', exit_=0)
            This is the top level help.
            <BLANKLINE>
            Usage:
                foo  (required, multi)
                    -f <file>
                    -o <file>  (required)
                bar <qwerty>
            <BLANKLINE>
            Use --help to see full information.

        Help for a particular Arg:

            >>> parser.parse('foo --help', exit_=0)
            Help for 'foo':
            <BLANKLINE>
            Do foo
            <BLANKLINE>
            Usage:
                foo  (required, multi)
                    -f <file>   Input file
                    -o <file>  (required)
                                Output file

        Help for a lower-level Arg:

            >>> parser.parse('foo -f -h', exit_=0)
            Help for 'foo':'-f <file>':
            <BLANKLINE>
            Input file
            <BLANKLINE>
            Usage:
                -f <file>
            <BLANKLINE>
            Use --help to see full information.

        Help text from the.help_text() method.

            >> parser.help_text()
            This is the top level help.
            <BLANKLINE>
            Usage:
                foo  (required, multi)
                                Do foo
                    -f <file>   Input file
                    -o <file>  (required)
                                Output file
                bar <qwerty>    Do bar
            Use --help to see full information.

        Lines are not wrapped if they end with backslash:

            >>> parser = Arg('',
            ...     help=r"""
            ...     this help is not \\
            ...     reformatted. \\
            ...     """)
            >>> parser.parse('--help', exit_=0)
            this help is not \\
            reformatted. \\
            <BLANKLINE>
            Usage:
    '''

    def __init__(self, syntax, subargs=None, help=None, required=False, multi=False):
        '''
        syntax:
            Text description of this argument, using space-separated items,
            each of which is to match an item in argv. Items are literal by
            default, match anything if inside angled brackets <...>, or match
            all remaining args if '...'. E.g.: '-d <files>' will match -d
            followed by one arg whose value will be available as .d.

            todo: Use <foo:type> to do automatic type conversion.
        subargs:
            If not None, a list of additional Arg instances to match.
        help:
            Help text for this item. Is passed through textwrap.dedent() etc so
            can be indented arbitrarily.
        required:
            If true this item is required.
        multi:
            If true we allow any number of these args.
        '''
        self.syntax = syntax
        self.subargs = subargs if subargs else []
        self.help_ = help
        self.required = required
        self.multi = multi
        self.parent = None
        self.match_remaining = False

        # We represent each space-separated element in <syntax> as an _ArgItem
        # in self.items. Each of these will match exactly one item in argv
        # (except for '...').
        #
        self.syntax_items = []
        syntax_items = syntax.split()
        self.name_raw = ''
        for i, syntax_item in enumerate(syntax_items):
            if i == 0:
                self.name_raw = syntax_item
            if i == len(syntax_items) - 1 and syntax_item == '...':
                self.match_remaining = True
                break
            item = Arg._ArgItem(syntax_item)
            self.syntax_items.append(item)
        if self.match_remaining and not self.syntax_items:
            self.name = 'remaining_'
        else:
            self.name = self.syntax_items[0].name if self.syntax_items else ''
        self._check_subargs()

    def add_subarg(self, subarg):
        '''
        Adds <subarg> to self.subargs.
        '''
        self.subargs.append(subarg)
        self._check_subargs()

    def parse(self, argv, exit_=True):
        '''
        Attempts to parse <argv>.

        On success:
            Returns an ArgResult instance, usually containing other nested
            ArgResult instances, representing <argv> after parsing.

        On failure:
            If the next un-matched item in argv is '-h' or '--help' we output
            appropriate help, then call sys.exit(0) if <exit_> is true else
            return None.

            Otherwise we output information about where things went wrong and
            call sys.exit(1) if <exit_> is true else return None.
        '''
        if isinstance(argv, str):
            argv = argv.split()
        value = ArgResult()
        failures = Arg._Failures(argv)
        n = self._parse_internal(argv, 0, value, failures, depth=0)

        if n != len(argv):
            # Failed to parse argv; latest failures were at argv[failures.pos].
            #
            if failures.pos < len(argv) and argv[failures.pos] in ('-h', '--help'):
                # Parse failed at -h or --help so show help.
                brief = argv[failures.pos] == '-h'

                # <failures> will have a list of Arg's, each of which has a
                # sequence of parents; it would be confusing to show help for
                # each of these Arg's so instead we show help for the the Arg
                # at the end of the longest common ancestor.
                #
                def ancestors(arg):
                    return ancestors(arg.parent) + [arg] if arg.parent else [arg]
                def common_path(paths):
                    if not paths:
                        return [self]
                    for n in range(len(paths[0])+1):
                        for path in paths:
                            if len(path) <= n or path[n] != paths[0][n]:
                                return paths[0][:n]
                paths = [ancestors(arg) for arg, extra in failures.args]
                path = common_path(paths)
                syntax = ''
                for arg in path:
                    if arg.syntax:
                        syntax += f'{arg.syntax!r}:'
                if syntax:
                    sys.stdout.write(f'Help for {syntax}\n\n')
                sys.stdout.write(arg.help_text(brief=brief))
                if brief:
                    sys.stdout.write('\nUse --help to see full information.\n')
            else:
                # Show information about the parse failures.
                sys.stdout.write(str(failures))

            if exit_:
                sys.exit(1)

            return

        if self.name == '' and value.__dict__:
            # Skip empty top-level.
            assert '_' in value._attr
            return value._attr['_']
        return value

    class _ArgItem:
        def __init__(self, syntax_item):
            if syntax_item.startswith('<') and syntax_item.endswith('>'):
                self.text = syntax_item[1:-1]
                self.literal = False
            else:
                self.text = syntax_item
                self.literal = True
            # self.parse() will return an ArgResult that uses self.name as
            # attribute name, so we need to make it a usable Python identifier.
            self.name = self.text
            while self.name.startswith('-'):
                self.name = self.name[1:]
            self.name = self.name.replace('-', '_')
            self.name = re.sub('[^a-zA-Z0-9_]', '', self.name)
            if self.name[0] in '0123456789':
                self.name = '_' + self.name
        def __repr__(self):
            return f'text={self.text} literal={self.literal}'

    def _check_subargs(self):
        '''
        Assert that there are no duplicate names in self.subargs.
        '''
        if self.subargs:
            assert isinstance(self.subargs, list)
            name_to_subarg = dict()
            for subarg in self.subargs:
                subarg.parent = self
                duplicate = name_to_subarg.get(subarg.name)
                assert duplicate is None, (
                        f'Duplicate name {subarg.name!r} in subargs of {self.syntax!r}:'
                        f' {duplicate.syntax!r} {subarg.syntax!r}'
                        )
                name_to_subarg[subarg.name] = subarg

    def _parse_internal(self, argv, pos, out, failures, depth):
        '''
        Tries to match initial item(s) in argv with self.syntax_items and
        self.subargs.

        On success we set/update <out> and return the number of argv items
        consumed. Otherwise we return None with <failures> updated.

        We fail if self.multi is false and out.<self.name> already exists.
        '''
        if not self.multi and getattr(out, self.name, None) is not None:
            # Already found.
            if self.syntax_items and pos < len(argv):
                item = self.syntax_items[0]
                if item.literal and item.text == argv[pos]:
                    failures.add(pos, None, f'only one instance of {self.syntax} allowed')
            return None

        # Match each item in self.syntax_items[] with an item in argv[],
        # putting non-literal items into values[].
        result = None
        for i, item in enumerate(self.syntax_items):
            if pos+i >= len(argv):
                failures.add(pos+i, self)
                return None
            if item.literal:
                if item.text != argv[pos+i]:
                    failures.add(pos+i, self)
                    return None
            else:
                if argv[pos+i].startswith('-'):
                    failures.add(pos+i, self, f'value must not start with "-"')
                    return None
                elif len(self.syntax_items) == 1:
                    result = argv[pos+i]
                else:
                    if result is None:
                        result = ArgResult()
                    result._set(item.name, item.name, argv[pos+i])

        if self.match_remaining:
            r = argv[pos+len(self.syntax_items):]
            if result is None:
                result = r
            else:
                result._set('remaining_', 'remaining_', r)
            n = len(argv) - pos
        else:
            n = len(self.syntax_items)

        if result is None:
            result = True
        # Condense <values> for convenience.
        #if not result or not result._attr:
        #    result = True
        #value = True if len(values) == 0 else values[0] if len(values) == 1 else values

        if self.subargs:
            # Match all subargs; we fail if any required subarg is not matched.
            subargs_n, subargs_out = self._parse_internal_subargs(argv, pos+n, failures, depth)
            if subargs_n is None:
                # We failed to match one or more required subargs.
                return None
            n += subargs_n
            result = subargs_out if result is True else (result, subargs_out)

        out._set(self.name if self.name else '_', self.name_raw, result, self.multi)

        item_list_ns = ArgResult()
        item_list_ns._set(self.name, self.name_raw, result)
        out._list.append((self.name, result, item_list_ns))

        return n

    def _parse_internal_subargs(self, argv, pos, failures, depth):
        '''
        Matches as many items in self.subargs as possible, in any order.

        Returns (n, out) where <n> is number of argv items consumed and <out>
        is an ArgResult with:
            ._attr
                Mapping from each matching subarg.name to value.
            ._dict
                Mapping from each matching subarg.name_raw to value.
            ._list
                List of (name, value, namespace).

        Returns (None, None) if we failed to match an item in self.subargs
        where .required is true.
        '''
        subargs_out = ArgResult()
        n = 0
        # Repeatedly match a single item in self.subargs until nothing matches
        # the next item(s) in argv.
        while 1:
            # Try to match one item in self.subargs.
            for subarg in self.subargs:
                nn = subarg._parse_internal(argv, pos+n, subargs_out, failures, depth+1)
                if nn is not None:
                    n += nn
                    break
            else:
                # No subarg matches the next item(s) in argv, so we're done.
                break

        # See whether all required subargs were found.
        for subarg in self.subargs:
            if subarg.required and not hasattr(subargs_out, subarg.name):
                return None, None

        value = ArgResult()

        # Copy subargs_out into <value>, setting missing argv items to None or
        # [].
        for subarg in self.subargs:
            v = getattr(subargs_out, subarg.name, [] if subarg.multi else None)
            value._set(subarg.name, subarg.name_raw, v)

        # Copy subargs_out._list into <value>, setting missing items to None.
        value._list = subargs_out._list
        for name, v, ns in value._list:
            assert len(ns._attr) == 1
            for subarg in self.subargs:
                if subarg.name != name:
                    ns._set(subarg.name, subarg.name_raw, None)
            assert len(ns._attr) == len(self.subargs)

        return n, value

    class _Failures:
        def __init__(self, argv):
            self.argv = argv
            self.pos = 0
            self.args = []
            self.misc = []
        def add(self, pos, arg, extra=None):
            if arg and not arg.name:
                log('top-level arg added to failures')
                log(exception_info())
            if pos < self.pos:
                return
            if pos > self.pos:
                self.args = []
                self.pos = pos
            if arg:
                self.args.append((arg, extra))
            else:
                self.misc.append(extra)
        def __str__(self):
            ret = ''
            if self.pos == len(self.argv):
                ret += f'Ran out of arguments'
            else:
                ret += f'Failed at argv[{self.pos}]={self.argv[self.pos]!r}'
            for i in self.misc:
                 ret += f', {i}'
            ret += f', expected one of:\n'
            for arg, extra in self.args:
                ret += f'    {arg.syntax}'
                more = []
                if arg.parent and arg.parent.name:
                    more.append(f'from {arg._path()}')
                if arg.required:
                    more.append('required')
                if extra:
                    more.append(extra)
                if more:
                    ret += f'  ({", ".join(more)})'
                ret += '\n'
            return ret

    def _path(self):
        if self.parent:
            p = self.parent._path()
            if p:
                return f'{self.parent._path()}:{self.name}'
        return self.name

    def help_text(self, prefix='', width=80, mid=None, brief=False):
        '''
        Returns help text for this arg and all subargs.

        prefix:
            Prefix for each line.
        width:
            Max length of any line.
        mid:
            Column in which to start subargs' help text. If None, we choose a
            value based on width.
        brief:
            If true, we only show brief information.
        '''
        if width and mid:
            assert mid < width
        if mid is None:
            mid = min(20, int(width/2))
        text = ''

        top_level = (prefix == '')
        if top_level:
            # Show self.help_ text without indentation.
            if self.help_:
                h = Arg._format(self.help_, prefix='', width=width, n=1 if brief else None)
                text += h + '\n\n'
            text += 'Usage:\n'
            if self.name:
                prefix += '    '
        if self.syntax_items:
            # Show syntax, e.g. '-s <files>'.
            text += f'{prefix}'
            for i, item in enumerate(self.syntax_items):
                if i: text += ' '
                text += item.text if item.literal else f'<{item.text}>'
            if self.match_remaining:
                text += ' ...'
            # Show flags, if any.
            extra = []
            if self.required:   extra.append('required')
            if self.multi:  extra.append('multi')
            if extra:
                text += f'  ({", ".join(extra)})'

            # Show self.help_ starting at column <mid>, starting on a second
            # line if we are already too close to or beyond <mid>.
            if not brief and self.help_ and not top_level:
                h = Arg._format(self.help_, mid*' ', width, n=1 if brief else None)
                if h:
                    if len(text) <= mid-2:
                        # First line of help will fit on current line.
                        h = h[len(text):]
                    else:
                        text += '\n'
                    text += h
            text += '\n'

        if self.subargs:
            for subarg in self.subargs:
                t = subarg.help_text( prefix + '    ', mid=mid, brief=brief)
                text += t

        assert text.endswith('\n')
        assert not text.endswith('\n\n'), f'len(self.subargs)={len(self.subargs)} text={text!r} self.help_={self.help_!r}'
        return text

    def __repr__(self):
        return f'Arg({self.syntax}: name={self.name})'

    @staticmethod
    def _format(text, prefix, width, n=None):
        '''
        Returns text formatted according to <prefix> and <width>. Does not end
        with newline.

        If <n> is not None, we return the first <n> paragraphs only.

        We split paragraphs on double newline and also when indentation
        changes:

        >>> t = Arg._format("""
        ... <foo>:
        ...     bar.
        ...
        ...     qwerty.
        ...
        ...     """,
        ...     ' '*4, 80,
        ...     )
        >>> print(t)
            <foo>:
                bar.
        <BLANKLINE>
                qwerty.
        '''
        def strip_newlines(text):
            while text.startswith('\n'):
                text = text[1:]
            while text.endswith('\n'):
                text = text[:-1]
            return text

        text = textwrap.dedent(text)
        text = strip_newlines(text)

        # Reformat using textwrap.fill(); unfortunately it only works on
        # individual paragraphs and doesn't handle indented text, so we have
        # to split into paragraphs, remember indentation of paragraph, dedent
        # paragraph, fill, indent, and finally join paragraphs back together
        # again.
        #
        paras = []
        indent_prev = -1
        def get_paras(text):
            '''
            Yields (indent, backslashe, text) for each paragraph in <text>,
            splitting on double newlines. We also split when indentation
            changes unless lines end with backslash. <backslash> is true iff
            text contains backslash at end of line.
            '''
            for para in text.split('\n\n'):
                indent_prev = None
                prev_backslash = False
                prev_prev_backslash = False
                i0 = 0
                lines = para.split('\n')
                for i, line in enumerate(lines):
                    m = re.search('^( *)[^ ]', line)
                    indent = len(m.group(1)) if m else 0
                    if i and not prev_backslash and indent != indent_prev:
                        yield indent_prev, prev_prev_backslash, '\n'.join(lines[i0:i])
                        i0 = i
                    backslash = line.endswith('\\')
                    if i == 0 or not prev_backslash:
                        indent_prev = indent
                    prev_prev_backslash = prev_backslash
                    prev_backslash = backslash
                yield indent_prev, prev_prev_backslash, '\n'.join(lines[i0:])
        for i, (indent, sl, para) in enumerate(get_paras(text)):
            if n is not None and i == n:
                break
            para = textwrap.dedent(para)
            # Don't fill paragraph if contains backslashes.
            if not sl:
                para = textwrap.fill(para, width - len(prefix))
            para = textwrap.indent(para, prefix + indent*' ')
            if indent <= indent_prev:
                # Put blank lines before less-indented paragraphs.
                paras.append('')
            paras.append(para)
            indent_prev = indent
        ret = f'\n'.join(paras)
        assert not ret.endswith('\n')
        return ret


if __name__ == '__main__':

    import doctest
    doctest.testmod(
            optionflags=doctest.FAIL_FAST,
            )
