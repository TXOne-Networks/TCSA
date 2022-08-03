import sys, threading, IPython
#https://stackoverflow.com/questions/24165374/printing-a-functions-local-variable-names-and-values

def locals_tracer(f, callback):
    gutsdata = threading.local()
    gutsdata.captured_locals = None
    gutsdata.tracing = False
    def trace_locals(frame, event, arg):
        if event == 'line':  # continue tracing
            return trace_locals
        if event.startswith('c_'):  # C code traces, no new hook
            return 
        if event == 'call':  # start tracing only the first call
            if gutsdata.tracing: return None
            gutsdata.tracing = True
            return trace_locals
        # event is either exception or return, capture locals, end tracing
        gutsdata.captured_locals = frame.f_locals.copy()
        return None

    def wrapper(*args, **kw):
        old_trace = sys.gettrace()
        sys.settrace(trace_locals)
        try:
            retval = f(*args, **kw)
        finally:
            # reinstate existing tracer, report, clean up
            sys.settrace(old_trace)
            
            if gutsdata.captured_locals:
                callback(gutsdata.captured_locals)
            gutsdata.captured_locals = None
            gutsdata.tracing = False
        return retval

    return wrapper