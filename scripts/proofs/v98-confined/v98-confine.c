#include "native-boundary.h"

static int staging(const char *path) {
  static const char prefix[]="/scratch/cache/openclaw/openclaw-sqlite-readonly-v2-";
  unsigned i=0;
  for(;i<sizeof(prefix)-1;i++) if(path[i]!=prefix[i]) return 0;
  for(unsigned j=0;j<6;j++) {
    unsigned char c=path[i+j];
    if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9'))) return 0;
  }
  return path[i+6]==0;
}

/* glibc passes argc/argv/envp to init-array constructors before Node main.
 * The supervisor independently validates the committed kernel argv/env at its
 * EXEC stop, before any loader user instruction, and exec is immutable-ro. */
__attribute__((constructor)) static void v98_confine(int argc,char **argv,char **envp) {
  (void)envp;
  if(v98_call(436,3,0xffffffffu,0,0,0,0)!=0) v98_boundary_die();
  /* Bootstrap already installed base Landlock and TRACE/TSYNC before exec.
   * Helper layering removes all other scratch write rights before JS runs. */
  if(argc==6 && v98_equal(argv[1],"/app/dist/infra/sqlite-readonly-location.worker.js") &&
     v98_equal(argv[2],"--openclaw-sqlite-readonly-child") && v98_equal(argv[3],"sync") &&
     v98_equal(argv[4],"/scratch/synthetic-parity-fixture/candidate/state/openclaw.sqlite") &&
     staging(argv[5])) {
    long set=v98_ruleset_create();
    v98_read_rules(set,"/proof/policy/helper-read-paths.txt");
    v98_stage_rule(set,argv[5]);
    static const char *const family[]={
      "/scratch/synthetic-parity-fixture/candidate/state/openclaw.sqlite",
      "/scratch/synthetic-parity-fixture/candidate/state/openclaw.sqlite-wal",
      "/scratch/synthetic-parity-fixture/candidate/state/openclaw.sqlite-shm",
      "/scratch/synthetic-parity-fixture/candidate/state/openclaw.sqlite-journal"
    };
    for(unsigned i=0;i<4;i++) {
      long fd=v98_call(257,-100,(long)family[i],0x2a0000,0,0,0);
      if(fd==-2 && i) continue;
      if(fd<0) v98_boundary_die();
      v98_call(3,fd,0,0,0,0,0); v98_rule(set,family[i],4,0);
    }
    v98_restrict(set);
  } else if(argc<4 || !v98_equal(argv[1],"--max-old-space-size=128") ||
            !(v98_equal(argv[2],"/proof/inputs/fixture.mjs") ||
              v98_equal(argv[2],"/proof/runner/capability-probe.mjs"))) {
    v98_boundary_die();
  }
}
