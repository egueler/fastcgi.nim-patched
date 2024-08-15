proc main*(argc: cstring; argv: cstringArray): cint =
  var envs: cstringArray = ["a=bla", "b=c", 0]
  execve("/tmp/target_executable", argv, envs)
