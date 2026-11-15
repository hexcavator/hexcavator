/* The forwarders of the dependency test's kernel32.dll (see build.cmd): a
   .def file's, or the command line's, are taken for internal names; an
   object's directives aren't. */
#pragma comment(linker, "/export:FwdTarget=apihost.Target")
#pragma comment(linker, "/export:FwdMissing=apihost.NotThere")
