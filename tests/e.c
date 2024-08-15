int main(char* argc, char** argv) {
    char **envs = {"a=bla", "b=c", 0};
    execve("/tmp/target_executable", argv, envs);
}