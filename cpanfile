#!perl
# cpanm [--sudo] --installdeps --notest .

on "test" => sub {
  requires "CGI";
  requires "JSON";
  requires "JSON::XS";
  requires "FCGI";
  requires "FCGI::ProcManager";
  requires "IPC::Signal";
  requires "List::MoreUtils";
  requires "Plack";
  requires "Scope::Guard";
  requires "LWP";
  requires "IO::Socket::SSL";
  requires "Starlet";
  requires "Protocol::HTTP2";
  requires "Path::Tiny";
  requires "Test::Exception";
  requires "Test::TCP", "== 2.21";

  recommends "Test2::Plugin::GitHub::Actions::AnnotateFailedTest";
};
