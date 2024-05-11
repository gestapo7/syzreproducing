// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package repro

import (
	"fmt"
	"math/rand"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/testutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func initTest(t *testing.T) (*rand.Rand, int) {
	iters := 1000
	if testing.Short() {
		iters = 100
	}
	return rand.New(testutil.RandSource(t)), iters
}

func TestBisect(t *testing.T) {
	ctx := &context{
		stats: new(Stats),
		logf:  t.Logf,
	}

	rd, iters := initTest(t)
	for n := 0; n < iters; n++ {
		var progs []*prog.LogEntry
		numTotal := rd.Intn(300)
		numGuilty := 0
		for i := 0; i < numTotal; i++ {
			var prog prog.LogEntry
			if rd.Intn(30) == 0 {
				prog.Proc = 42
				numGuilty++
			}
			progs = append(progs, &prog)
		}
		if numGuilty == 0 {
			var prog prog.LogEntry
			prog.Proc = 42
			progs = append(progs, &prog)
			numGuilty++
		}
		progs, _ = ctx.bisectProgs(progs, func(p []*prog.LogEntry) (bool, error) {
			guilty := 0
			for _, prog := range p {
				if prog.Proc == 42 {
					guilty++
				}
			}
			return guilty == numGuilty, nil
		})
		if numGuilty > 8 && len(progs) == 0 {
			// Bisection has been aborted.
			continue
		}
		if len(progs) != numGuilty {
			t.Fatalf("bisect test failed: wrong number of guilty progs: got: %v, want: %v", len(progs), numGuilty)
		}
		for _, prog := range progs {
			if prog.Proc != 42 {
				t.Fatalf("bisect test failed: wrong program is guilty: progs: %v", progs)
			}
		}
	}
}

func TestSimplifies(t *testing.T) {
	opts := csource.Options{
		Threaded:     true,
		Repeat:       true,
		Procs:        10,
		Sandbox:      "namespace",
		NetInjection: true,
		NetDevices:   true,
		NetReset:     true,
		Cgroups:      true,
		UseTmpDir:    true,
		HandleSegv:   true,
		Repro:        true,
	}
	var check func(opts csource.Options, i int)
	check = func(opts csource.Options, i int) {
		if err := opts.Check(targets.Linux); err != nil {
			t.Fatalf("opts are invalid: %v", err)
		}
		if i == len(cSimplifies) {
			return
		}
		check(opts, i+1)
		if cSimplifies[i](&opts) {
			check(opts, i+1)
		}
	}
	check(opts, 0)
}

func generateTestInstances(ctx *context, count int, execInterface execInterface) {
	for i := 0; i < count; i++ {
		ctx.bootRequests <- i
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for vmIndex := range ctx.bootRequests {
			ctx.instances <- &reproInstance{execProg: execInterface, index: vmIndex}
		}
	}()
	wg.Wait()
}

type testExecInterface struct {
	t *testing.T
	// For now only do the simplest imitation.
	run func([]byte) (*instance.RunResult, error)
}

func (tei *testExecInterface) Close() {}

func (tei *testExecInterface) RunCProg(p *prog.Prog, duration time.Duration,
	opts csource.Options) (*instance.RunResult, error) {
	return tei.RunSyzProg(p.Serialize(), duration, opts)
}

func (tei *testExecInterface) RunSyzProg(syzProg []byte, duration time.Duration,
	opts csource.Options) (*instance.RunResult, error) {
	return tei.run(syzProg)
}

func prepareTestCtx(t *testing.T, log string) *context {
	mgrConfig := &mgrconfig.Config{
		Derived: mgrconfig.Derived{
			TargetOS:     targets.Linux,
			TargetVMArch: targets.AMD64,
		},
		Sandbox: "namespace",
	}
	var err error
	mgrConfig.Target, err = prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	reporter, err := report.NewReporter(mgrConfig)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := prepareCtx([]byte(log), mgrConfig, nil, reporter, 3)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

const testReproLog = `
2015/12/21 12:18:05 executing program 1:
getpid()
pause()
2015/12/21 12:18:10 executing program 2:
getpid()
getuid()
2015/12/21 12:18:15 executing program 1:
alarm(0x5)
pause()
2015/12/21 12:18:20 executing program 3:
alarm(0xa)
getpid()
`

// Only crash if `pause()` is followed by `alarm(0xa)`.
var testCrashCondition = regexp.MustCompile(`(?s)pause\(\).*alarm\(0xa\)`)

func testExecRunner(log []byte) (*instance.RunResult, error) {
	crash := testCrashCondition.Match(log)
	if crash {
		ret := &instance.RunResult{}
		ret.Report = &report.Report{
			Title: `some crash`,
		}
		return ret, nil
	}
	return &instance.RunResult{}, nil
}

// Just a pkg/repro smoke test: check that we can extract a two-call reproducer.
// No focus on error handling and minor corner cases.
func TestPlainRepro(t *testing.T) {
	ctx := prepareTestCtx(t, testReproLog)
	go generateTestInstances(ctx, 3, &testExecInterface{
		t:   t,
		run: testExecRunner,
	})
	result, _, err := ctx.run()
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(`pause()
alarm(0xa)
`, string(result.Prog.Serialize())); diff != "" {
		t.Fatal(diff)
	}
}

// There happen to be transient errors like ssh/scp connection failures.
// Ensure that the code just retries.
func TestVMErrorResilience(t *testing.T) {
	ctx := prepareTestCtx(t, testReproLog)
	fail := false
	go generateTestInstances(ctx, 3, &testExecInterface{
		t: t,
		run: func(log []byte) (*instance.RunResult, error) {
			fail = !fail
			if fail {
				return nil, fmt.Errorf("some random error")
			}
			return testExecRunner(log)
		},
	})
	result, _, err := ctx.run()
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(`pause()
alarm(0xa)
`, string(result.Prog.Serialize())); diff != "" {
		t.Fatal(diff)
	}
}

func TestTooManyErrors(t *testing.T) {
	ctx := prepareTestCtx(t, testReproLog)
	counter := 0
	go generateTestInstances(ctx, 3, &testExecInterface{
		t: t,
		run: func(log []byte) (*instance.RunResult, error) {
			counter++
			if counter%4 != 0 {
				return nil, fmt.Errorf("some random error")
			}
			return testExecRunner(log)
		},
	})
	_, _, err := ctx.run()
	if err == nil {
		t.Fatalf("expected an error")
	}
}

const example = `
open(&(0x7f0000000100)='./bus\x00', 0x143142, 0x0)
r0 = open(&(0x7f0000000040)='./bus\x00', 0x10103e, 0x0)
mmap(&(0x7f0000000000/0x600000)=nil, 0x600000, 0x7ffffe, 0x4002011, r0, 0x0)
ftruncate(r0, 0x20cf01)
open(&(0x7f00000001c0)='./file1\x00', 0x1cd27e, 0x0)
open(&(0x7f0000000180)='./bus\x00', 0x14927e, 0x0)
write$FUSE_STATFS(0xffffffffffffffff, &(0x7f00000000c0)={0x60}, 0x60)

executing program 3:
syslog(0x2, &(0x7f0000000040), 0x0)

executing program 3:
r0 = bpf$BPF_PROG_RAW_TRACEPOINT_LOAD(0x5, &(0x7f0000000680)={0x10, 0x4, &(0x7f0000000380)=ANY=[@ANYBLOB="1802000000c4400000000000e0feff00850000000f00000095"], &(0x7f00000000c0)='GPL\x00'}, 0x90)
r1 = bpf$MAP_CREATE(0x0, &(0x7f00000023c0)=@base={0xe, 0x4, 0x8, 0xb}, 0x48)
bpf$BPF_PROG_DETACH(0x8, &(0x7f00000001c0)={@map=r1, r0, 0x7}, 0x10)

[  620.001474][  T140] team0 (unregistering): Port device team_slave_1 removed
executing program 3:
clock_adjtime(0x0, &(0x7f0000000000)={0xffff, 0x0, 0x100000000000000})

[  620.045770][  T140] team0 (unregistering): Port device team_slave_0 removed
executing program 3:
r0 = socket$nl_netfilter(0x10, 0x3, 0xc)
sendmsg$NFT_BATCH(r0, &(0x7f000000c2c0)={0x0, 0x0, &(0x7f0000000200)={&(0x7f0000000440)=ANY=[@ANYBLOB="140000001000010000000000000000000000000a28000000000a0101000000005e1affd5020000000900010073797a300000000008000240000000032c000000030a01030000e6ff00000000020000000900010073797a30000000000900030073797a320000000014000000110001"], 0x7c}}, 0x0)
sendmsg$NFT_BATCH(r0, &(0x7f00000000c0)={0x0, 0x0, &(0x7f0000000b00)={&(0x7f00000002c0)={{0x14}, [@NFT_MSG_NEWRULE={0x64, 0x6, 0xa, 0x401, 0x0, 0x0, {0x2}, [@NFTA_RULE_EXPRESSIONS={0x38, 0x4, 0x0, 0x1, [{0x34, 0x1, 0x0, 0x1, @payload={{0xc}, @val={0x24, 0x2, 0x0, 0x1, [@NFTA_PAYLOAD_LEN={0x8}, @NFTA_PAYLOAD_SREG={0x8, 0x5, 0x1, 0x0, 0xb}, @NFTA_PAYLOAD_OFFSET={0x8}, @NFTA_PAYLOAD_BASE={0x8}]}}}]}, @NFTA_RULE_TABLE={0x9, 0x1, 'syz0\x00'}, @NFTA_RULE_CHAIN={0x9, 0x2, 'syz2\x00'}]}], {0x14}}, 0x8c}}, 0x0)

executing program 3:
r0 = socket$nl_route(0x10, 0x3, 0x0)
recvmmsg(r0, &(0x7f0000004340)=[{{&(0x7f0000000380)=@l2tp6, 0x80, 0x0}}], 0x1, 0x0, 0x0)
r1 = openat$cgroup_ro(0xffffffffffffff9c, &(0x7f00000001c0)='blkio.bfq.io_wait_time_recursive\x00', 0x275a, 0x0)
mmap(&(0x7f0000000000/0xb36000)=nil, 0xb36000, 0x2, 0x28011, r1, 0x0)
ftruncate(r1, 0x6)
sendmsg$nl_route(r0, &(0x7f0000000000)={0x0, 0x0, &(0x7f0000000040)={&(0x7f0000000200)=@RTM_DELMDB={0x18, 0x55, 0x32f}, 0x18}}, 0x0)

executing program 1:
r0 = bpf$MAP_CREATE_CONST_STR(0x0, &(0x7f0000000340)={0x2, 0x4, 0x8, 0x1, 0x80, 0x0, 0x0, '\x00', 0x0, 0x0}, 0x48)
bpf$BPF_MAP_CONST_STR_FREEZE(0x16, &(0x7f0000000cc0)={r0}, 0x4)
r1 = bpf$MAP_CREATE(0x0, &(0x7f00000000c0)=@base={0x1b, 0x0, 0x0, 0x8000}, 0x48)
r2 = bpf$PROG_LOAD(0x5, &(0x7f0000000340)={0x6, 0x1c, &(0x7f0000000480)=@ringbuf={{}, {{0x18, 0x1, 0x1, 0x0, r1}}, {}, [@snprintf={{}, {}, {}, {}, {}, {}, {}, {}, {}, {0x18, 0x3, 0x2, 0x0, r0}}], {{}, {}, {0x85, 0x0, 0x0, 0x85}}}, &(0x7f0000000c40)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_PROG_TEST_RUN(0xa, &(0x7f0000000240)={r2, 0xfca804a0, 0x0, 0x18a0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x50)

[  620.366899][T15853] netdevsim netdevsim4 netdevsim3: renamed from eth3
[  620.398998][T15768] veth0_vlan: entered promiscuous mode
[  620.452795][T15768] veth1_vlan: entered promiscuous mode
[  620.538189][T16025] loop2: detected capacity change from 0 to 32768
[  620.611267][T15768] veth0_macvtap: entered promiscuous mode
[  620.625107][T16025] XFS (loop2): Mounting V5 Filesystem a2f82aab-77f8-4286-afd4-a8f747a74bab
executing program 1:
r0 = bpf$PROG_LOAD(0x5, &(0x7f0000000200)={0xc, 0xe, &(0x7f0000001240)=ANY=[@ANYBLOB="b702000003000000bfa30000000000000703000000feffff7a0af0ff0100000079a4f0ff00000000b7060000ffffffff2d6405000000000065040400010000000404000001007d60b7030000000000006a0a00fe00000000850000000d000000b70000000000000095000000000000005ecefab8f2e85c6c1ca711fcd0cdfa146ec561750379585e5a076d839240d29c034055b67dafe6c8dc3d5d0f65acc0d06d1a1434e4d5b3185fec0e07004e60c08dc8b8dbf11e6e94d75938321a3aa502cd2424a66e6d2ef831ab7ea0c34f17e3946ef3bb622e03b538dfd8e012e79578e51bc53099e90f4580d760551b5b341a29f31e3106d1ddd6152f7cbdb9cd38bdb2209c67deca8eeb9c15ab0300817ac61e4dd11183a13477bf7e860e3670ef0e789f65f1328d6704902cbe7bc04b82d2789cb132b8667c2147661df28d9961b63e1a9cf6c2a660a1fe3c184b751c51160fb20b1c690220b87b20581e7be6ba0dc001c4110555850915148ba532e6ea09c346dfebd38608b3280080005d9a9500000000000000334d83239dd27080851dcac3c12233f9a1fb9c2aec61ce63a38d2fd50117b89a9ab359b4eea0c6e95767d42b4e54861d0227dbfd2e6d7f715a7f3deadd713089856f757036303767d2e24f29e5dad9796edb697a8ad004eea0182babd18cac1bd4f4390af9a9ceafd0002cab154ad029a1090000002780870014f51c3c975d5aec84222fd3a0ec4be3e563112f0b39501aafe234870072858dc06e7c337642d3e5a815232f5e16c1b30c3a6a71bc85018e5ff22dc518afc9ffc2cc788bee1b47683db01a2f9398685211dfbbae3e2ed0a50e7313bff5d4c391ddece00fc772dd6b4d4de2a41990f05ca3bdfc92c88c5b8dcd36e7487afa407e2edfae4f390a8337841cef386e22cc22ee17476d738952229682e24b92533ac2a9f5a699593f084419cae0b4532bcc97d3ae526aca54183fb01c73f979ca9857399537f5831808b0dc2a2d0e0000000000000578673f8b6e74ce23877a6b24db0e067345560942fa629fbef2461c96a088a22e8b15c3e233db00002e30d46a9d24d37cef099ece729aa218f9f44a3210223fdae7ed04935c3c90d3add8eebc8619d73415cda2130f5011e4845535a8b90dfae158b94f50adab988dd8e12baf5cc9398fff00404d5d99f82e20ee6a8c88e18c2977aab37d9ac4cfc1c7b400000000000007ff57c39495c826b956ba859ac8e3c177b91bd7d5e41ff868f7ca1664fe2f3ced846891180604b6dd2499d16d7d9158ffffffff00000000ef069dc42749a89f854797f29d0000002d8c38a967c1bbe09315c29877a308bcc87dc3addb08141bdee5d27874b2f663ddeef0005b3d96c7aabf4df517d90bdc01e73835d50200a90800c66ee2b1ad76dff9f9003f07000099d4894ee7f8249dc1e3428d2129369ee1b85af6eb2eea0d0df414b315f651c8412392191fa83ee830548f11e1036a8debd64cbe359454a3f2239cfe35f81b7a490f167e6d5c1109000000000000000042b8ff8c21ad702ccacad5b39eef213d1ca296d2a27798c8ce2a305c0c7d35cf4b22549a4bd92052188bd1f285f653b621491dc6aaee0200e2ff08644fb94c06006eff1be2f633c1d987595ec3db58a7bb3042ec3f771f7a1338a5c3dd35e926049fe86e09c58e273cd905deb28c13c1ed1c0d9cae846bcbfa8cce7b893e578af7dc7d5e87d44ff828de453f34c2b18660b080efc707e676e1fb4d5825c0ca177a4c7fbb4eda0545c00f576b2b5cc7f819abd0f885cc4806f40300966fcf1e54f5a2d38708294cd6f496e5dee734fe7da3770845cf442d488afd80e17000000000000000000000000000000000000000000000000000005205000000dc1c56d59f35d367632952a93466ae595c6a8cda690d192a070886df42b27098773b45198b4a34ac977ebd4450e121d01342703f5bf030e935878a6d169c80aa4252d4ea6b8f6216ff202b5b5a182cb5e838b307632d03a7ca6f6d0339f9953c3093c3690d10ecb65dc5b47481edbf1f000000000000004d16d29c28eb5167e9936ed327fb237a56224e49d9ea955a5f0dec1b3ccd35364600000000000000000000000000000000000000000000000000000000000026ded4dd6fe1518cc7802043ecfe69f743f1213bf8179ecd9e5a225d67521dc728eac7d80a5656ac2cbde21d3ebfbf69ff861f4394836ddf128d6d19079e64336e7c676505c78ad67548f4b192be1827fcd95cf107753cb0a6a979d3db08407081c6281e2d8429a8639034a75f4c7df3ea8fc2018d07af1491ef060cd4403a099f32468f65bd06b4092140faed0c329be610c3082d43e121861b5cc03f1a1561f0589e0d12969bc982ff5d8e9b986c0c6c747d9a1cc500bb892c3a16ff10feea20bdac0000000000000000ca06f256c8028e0f9b4c8787361f3289f86a6826c69fa35ba5cbc3f2db1516ffc5c6e3fa618b24a6ce16d6c7010bb37b61fa0a2d8974e69115d33394e86e4b838297ba20f96936b7e4746e92dea6c5d1d33d84d96b50fb000000ae07c65b71088dd7d5d1e1bab9000000000000000000000000b5ace293bec833c13e3229432ad71d646218b5229dd88137fc7c59aa242af3bb4efb82055a3b61227ad40f52c9f2500579aca11033bb9cc16bd83a00840e31d828ec78e116ae46c4897e2795b6ff92e9a1e24b0b855c02f2b7add58ffb25f339297729a7a51810134d3dfbf71f6516737be55c06d9cdcfb1e2bb10b50000eb4acff90756dba1ecf9f58afd3c19b5c4558ba9af6b7333c894a1fb29ade9ad75c9c022e8d03fe28bc358684492aa771dbfe80745fe89ad349ffaad76ff9dd643796caffdf67af5dd476c37e7e9a84e2e5da2696e285a59b53f2fb0e16d8262c080c159ce1d9bc7ef3e3f40c14089c82759106f422582b42e3e8484ea5a6ad9aa520000afe0e0caea1ad4cb23f3c2b8a0f455ba69ea284c268d54b43158a8b1d128d02af263b3dc1cab794c9ac57a2a7332f4d8764c302ccd5aac114482b619fc575aa0dd2777e881e29a854380e2f1e49db5a1517ec40bb3fa44f9959bad67ccaba76408da35c9f1534c8bd48bbd61627a2e0a74b5e6aefb7eee403502734137ff47257f164391c673b6079e65d7295eed164ca63e4ea26dce0fb3ce0f6591d80dfb8f386bb74b5589829b6b0679b5d6fccbecfae5553d9950d48c774eaa35b24fce69a20d8bc410d9f48bf7eac90529cd6af061c9e53addddc620ce73c5d177e3d097159f2768636fc10276c6a0adc57483b3f7083f66b87ef296ee85e9bb70a3009a5d30f479e293a3302e11350ea857b37e76ca2f50378e4092ce2c574ad278b9b7b717c571afb2077b019fd9d89efd59b41f051ec5a8ff87ecc8df917a1e386d849fcd10e2f9ca52e02339c2f4666b0c545e25f1cd62421c28d25994be0cff7271a0dee38d7ac4ac736b090e1d29f981179186e4000000000000646174b55d251f7f8ca5ccc22a5efb33b237eff5597a3c3a5f3a9bb54abb40e54593e1a7ce4cfa17b3c3fe91c06363496341eae20dcc59b6179b32ddddef5c34000096a54c0c571a91878f61f74912e2299e5501d4d6943bfd74c856511726f0ac8f7d17f1c6b4451c1bcdc6b6e1700e4cd87709d97afc5423c96fa981873d4369b04bbf1fb9f68f17991540868e408201ad1a74179e489aa61f021a437a3fa935588be2068f7ff9b253106326fde795e530b93626cc68e06e602198724249b4445eef08401cd1a3e266db41474e69902e4d8f5da4e94cc36794258fd4032de7ab36bc24c5efd5c8495c1ccd580033c55725f2d60354f8ad5914a0155eaa743350ddb388f486b6de0549ef3b1b3c3b7d4d3a830ff39885776119408029be3788dd8422b1ab7b4c9d5b7d8682fd759c713108e1bdfc64b9121bbf07099def5c0ce3c861ae4b5cad8bba5a0b6059b9ef90c2f96a59320309e25df89484522bb1d6eaa92164f9e4042cb689a45a898354c17b08705205a9189772bcbcb6414e44b33a2470d3bc16f761c33f565b9da5e7991ad8482579cc1b16c1fcec815a5482ae8b1779c5e339971a6ec1217bcfd1ef24284de8a0a9f068f297037d6478c2434a9a18dcc6c7c791e444a79d7ce37f9cf2a434b9048ca6a2fa254aa02cd098026798a6d336348af0fc11fa2809a5ebbe17ca4d0f889d518f64ee50f562b5fdb1f76d4a7fe14701f8ed0c6a55d66a6efea3e449e6b4783d66661a92f174"], &(0x7f0000000340)='syzkaller\x00'}, 0x48)
bpf$BPF_PROG_TEST_RUN(0xa, &(0x7f0000000080)={r0, 0x18000000000002a0, 0x26, 0x0, &(0x7f0000000100)="b9ff0b076859268cb89e14f088a847e0ffff200000000029000aac141440e05968e249e832f0", 0x0, 0x0, 0x60000000, 0x0, 0x0, 0x0, 0x0}, 0x50)

executing program 3:
bpf$ENABLE_STATS(0x20, 0x0, 0x0)
r0 = bpf$PROG_LOAD(0x5, &(0x7f00002a0fb8)={0x16, 0x4, &(0x7f00000004c0)=ANY=[@ANYBLOB="850000002a0000003500000000000000850000000500000095000000000000001b90b31a08f54ff40571eda5c56ad924a10c7b1e6003c9325fea577f8e56fe212b358f1d0838c8119ed74e74552ce4e6c8093375e35c8250f448a6a31260c2f9fbb70400000000000000b08b7aab5fd5d24dcff1ca14025b73c2da8f550900000000000000c340b111fcee90d6d90100000001000000babdee5b76635ce4f35f985e434196b5699ba66b9cb05e5259a1f61cafa3586a2228c4581dc29931a4ca0f4967706596014dc06b99b9c9ba49b34e516e0baed5cca7aeeb0d5dcdce0900000000000100ef363c9f5ca80b125dabc3adab1179388e76c44e7328318078af6a0a1a248a7b2ca42a05f4b033e9d8a7880a116a60bd69a463a75045e8950a8e03000000000000008c4e7c6037b670a823e59267ae980c73ba09410000000000000000000000000000000042f7ae3d341b2a8e0c1681be5db38db3bf61f7ede5efbf55df1ee21b8e21b7a4a0bbc1d6a5483477260c03bf09959a71dac6b9f67019fe6ddacf40aed79f018c9fb9e9fc69425618b0d46811cff20f7b13e3e35c670b87bae02b63ebb47ca8e16be95b2ec5bde931fd425b3944783b922733b688b96e998bf39a2213f05ef1aad563d787d58d37cf2236ee2f00decc43c496fe7b27f0d98c0754bc7c305726ef314eb082d2989f2481d71f96c2d175145cec2251d7c080c782af32edd0ae00d83cfcd3d5a7abb0175a6be378acd0bbdc5c"], &(0x7f0000000140)='GPL\x00', 0x0, 0xa0, &(0x7f0000000180)=""/153}, 0x15)
bpf$BPF_PROG_TEST_RUN(0xa, &(0x7f0000000440)={r0, 0x0, 0xe, 0x2000000, &(0x7f00000000c0)="61df712bc884fed5722780b6c2a7", 0x0, 0xa68}, 0x28)

[  620.735159][T15768] veth1_macvtap: entered promiscuous mode
[  620.741062][T16025] XFS (loop2): Ending clean mount
executing program 1:
r0 = socket$nl_route(0x10, 0x3, 0x0)
sendmsg$nl_route(r0, &(0x7f0000000080)={0x0, 0x0, &(0x7f0000000000)={&(0x7f0000000140)=@newlink={0x40, 0x10, 0x581, 0x0, 0x0, {}, [@IFLA_LINKINFO={0x20, 0x12, 0x0, 0x1, @bridge={{0xb}, {0x10, 0x2, 0x0, 0x1, [@IFLA_BR_MCAST_QUERIER_INTVL={0xc}]}}}]}, 0x40}}, 0x0)
r1 = socket$nl_generic(0x10, 0x3, 0x10)
r2 = socket$inet6(0xa, 0x3, 0x88)
bind$inet6(r2, &(0x7f0000000000)={0xa, 0x0, 0x0, @mcast2, 0xa}, 0x1c)
setsockopt$SO_BINDTODEVICE(r2, 0x1, 0x19, 0x0, 0x0)
syz_emit_ethernet(0x83, &(0x7f0000000040)=ANY=[@ANYBLOB="aaaaaaaaaaaaaaaaf9ff030486dd601b8b97004d88c19e9ace00000000000000002100000002ff020000000000000000000000000001"], 0x0)
r3 = syz_genetlink_get_family_id$tipc(&(0x7f0000000440), 0xffffffffffffffff)
prlimit64(0x0, 0xe, &(0x7f0000000140)={0x8}, 0x0)
sched_setscheduler(0x0, 0x1, &(0x7f0000000080)=0x7)
r4 = socket(0x840000000002, 0x3, 0xfa)
connect$inet(r4, &(0x7f0000000140)={0x2, 0x0, @remote}, 0x10)
sendmmsg$inet(r4, &(0x7f0000005240), 0x4000095, 0x0)
r5 = socket$inet6_tcp(0xa, 0x1, 0x0)
listen(r5, 0x0)
listen(r5, 0x0)
r6 = openat$kvm(0xffffffffffffff9c, &(0x7f0000000000), 0x0, 0x0)
socket$nl_route(0x10, 0x3, 0x0)
r7 = ioctl$KVM_CREATE_VM(r6, 0xae01, 0x0)
ioctl$KVM_CREATE_IRQCHIP(r7, 0xae60)
r8 = ioctl$KVM_CREATE_VCPU(r7, 0xae41, 0x0)
sendto$inet6(0xffffffffffffffff, &(0x7f0000000080)="44f9b108b1cdc885c9c533d21f474bec8b", 0x11, 0x0, 0x0, 0x0)
ioctl$KVM_CAP_HYPERV_SYNIC2(r8, 0x4068aea3, &(0x7f00000008c0))
ioctl$KVM_SET_MSRS(r8, 0x4008ae89, &(0x7f0000000080)=ANY=[@ANYBLOB="010000000000000090000040"])
sendmsg$TIPC_CMD_SHOW_LINK_STATS(r1, &(0x7f0000000500)={0x0, 0x0, &(0x7f00000004c0)={&(0x7f0000000480)={0x1c, r3, 0x1, 0x0, 0x0, {{}, {0x0, 0x410c}, {0x14, 0x14, 'broadcast-link\x00'}}}, 0x30}}, 0x0)

[  620.869333][   T29] audit: type=1800 audit(1715377300.394:980): pid=16025 uid=0 auid=4294967295 ses=4294967295 subj=_ op=collect_data cause=failed(directio) comm="syz-executor.2" name="file1" dev="loop2" ino=1062 res=0 errno=0
[  620.892938][T15768] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3e) already exists on: batadv_slave_0
[  620.939702][T15768] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
[  620.950897][  T927] XFS (loop2): Metadata CRC error detected at xfs_allocbt_read_verify+0x41/0xd0, xfs_bnobt block 0x8 
[  620.962934][T15768] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3e) already exists on: batadv_slave_0
executing program 3:
bpf$BPF_PROG_RAW_TRACEPOINT_LOAD(0x5, &(0x7f0000000440)={0x11, 0x8, &(0x7f00000002c0)=@framed={{0x18, 0x8}, [@func={0x85, 0x0, 0x1, 0x0, 0x3}, @initr0, @exit, @alu={0x7, 0x1, 0xb, 0x0, 0xa}]}, &(0x7f0000000000)='GPL\x00', 0x2}, 0x90)

[  620.984567][  T927] XFS (loop2): Unmount and run xfs_repair
[  620.990550][T15768] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
[  621.000800][  T927] XFS (loop2): First 128 bytes of corrupted metadata buffer:
[  621.009324][  T927] 00000000: 41 42 33 42 00 00 00 02 ff ff ff ff ff ff ff ff  AB3B............
[  621.018386][T15768] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3e) already exists on: batadv_slave_0
[  621.031202][  T927] 00000010: 00 00 00 00 00 00 00 08 00 00 00 01 00 00 00 10  ................
[  621.040294][T15768] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
[  621.051910][  T927] 00000020: a2 f8 2a ab 77 f8 42 86 af d4 a8 f7 00 a7 4b ab  ..*.w.B.......K.
[  621.061031][T15768] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3e) already exists on: batadv_slave_0
[  621.071717][  T927] 00000030: 00 00 00 00 5b fd 4f dd 00 00 00 05 00 00 00 01  ....[.O.........
[  621.081212][T15768] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
[  621.091267][  T927] 00000040: 00 00 02 36 00 00 0d ca 00 00 00 00 00 00 00 00  ...6............
[  621.102950][T15768] batman_adv: batadv0: Interface activated: batadv_slave_0
[  621.111179][  T927] 00000050: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
[  621.131181][  T927] 00000060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
[  621.165927][  T927] 00000070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
[  621.177303][T16025] XFS (loop2): metadata I/O error in "xfs_btree_read_buf_block+0x36f/0x5b0" at daddr 0x8 len 8 error 74
[  621.199928][T15853] 8021q: adding VLAN 0 to HW filter on device bond0
[  621.238776][T15768] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3f) already exists on: batadv_slave_1
[  621.258437][T16025] XFS (loop2): Metadata I/O Error (0x1) detected at xfs_trans_read_buf_map+0x663/0xad0 (fs/xfs/xfs_trans_buf.c:296).  Shutting down filesystem.
[  621.279415][T15768] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
executing program 3:
sendmsg$nl_route(0xffffffffffffffff, &(0x7f0000000080)={0x0, 0x0, 0x0}, 0x0)
madvise(&(0x7f0000000000/0x600000)=nil, 0x600003, 0x15)
r0 = socket$kcm(0x29, 0x5, 0x0)
getsockopt$kcm_KCM_RECV_DISABLE(r0, 0x119, 0x2, 0x0, 0x20000007)

[  621.322907][T15768] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3f) already exists on: batadv_slave_1
[  621.327003][T16025] XFS (loop2): Please unmount the filesystem and rectify the problem(s)
[  621.375021][T15768] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
[  621.397841][T15768] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3f) already exists on: batadv_slave_1
executing program 2:
r0 = creat(&(0x7f0000000080)='./file0\x00', 0x0)
close(r0)
r1 = socket$tipc(0x1e, 0x5, 0x0)
setsockopt$TIPC_GROUP_JOIN(r1, 0x10f, 0x87, &(0x7f0000000000)={0x42}, 0x10)
mount$9p_fd(0x0, &(0x7f0000000180)='./file0\x00', &(0x7f00000002c0), 0x0, &(0x7f00000000c0)=ANY=[@ANYBLOB='trans=fd,rfdno=', @ANYRESHEX=r0, @ANYBLOB=',wfdno=', @ANYRESHEX=r1])

[  621.429864][T15768] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
[  621.464548][T15768] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3f) already exists on: batadv_slave_1
executing program 3:
r0 = syz_open_dev$dri(&(0x7f0000000000), 0x0, 0x0)
r1 = syz_open_dev$dri(&(0x7f00000008c0), 0xd21, 0x0)
ioctl$DRM_IOCTL_MODE_GETRESOURCES(r1, 0xc04064a0, &(0x7f00000001c0)={0x0, &(0x7f00000000c0)=[<r2=>0x0], 0x0, 0x0, 0x0, 0x1})
r3 = openat$capi20(0xffffffffffffff9c, &(0x7f0000000000), 0x408000, 0x0)
syz_emit_ethernet(0x2a, &(0x7f00000000c0)={@multicast, @broadcast, @void, {@ipv4={0x800, @udp={{0x5, 0x4, 0x0, 0x0, 0x1c, 0x0, 0x0, 0x0, 0x2f, 0x0, @rand_addr, @empty}, {0x1, 0x0, 0x8}}}}}, 0x0)
ioctl$CAPI_MANUFACTURER_CMD(r3, 0x541b, 0x0)
ioctl$DRM_IOCTL_MODE_GETCRTC(r1, 0xc06864a1, &(0x7f00000003c0)={0x0, 0x0, r2, <r4=>0x0})
ioctl$DRM_IOCTL_MODE_GETFB2(r1, 0xc06864ce, &(0x7f0000000440)={r4, 0x0, 0x0, 0x0, 0x0, [<r5=>0x0], [], [0x0, 0xfffffffc], [0x0, 0x0, 0x40000]})
ioctl$DRM_IOCTL_MODE_CREATE_DUMB(r0, 0xc02064b2, &(0x7f0000000140)={0x3ff, 0x2, 0xb5})
r6 = syz_open_dev$tty1(0xc, 0x4, 0x1)
r7 = dup(r6)
write$UHID_INPUT(r7, &(0x7f0000002080)={0xf, {"a2e3ad21e08eeb661b5b090987f70e06d038e7ff7fc6e5539b0d650e8b089b3f361cc9090890e0878f0e1ac6e7049b3345959b649a240d5b67f3988f7ef319520100ffe8d178708c523c921b1b5b31070d07440936cd3b78130daa61d8e8040000005802b77f07227227b7ba67e0e78657a6f5c2a874e62a9ccdc0d31a0c9f318c0da1993bd160e233df4a62179c6f30e065cd5b91cd0ae193973735b36d5b1b63dd1c00305d3f46635eb016d5b1dda98e2d749be7bd1df1fb3b231fdcdb5075a9aaa1b469c3090000000000000075271b286329d169934288fd789aa37d6e98b224fd44b65b31334ffc55cc82cd3ac32ecdb08ced6f9081b4dd0d8b38f3cd4498bee8006a0841bdb114f6b76383709d8f5c554336909fda039aec54a1236e80f6a8abadea7662496bddbb42be6bfb2f17959d1f416e56c71b1931870262f5e801119242ca026bfc821e7e7daf2451138e645bb80c617669314e2fbe70de98ec76a9e40dad47f36fd9f7d0d42a4b5f1185ccdcf16ff46295d8a0fa17713c5802630933a9a34af674f3f39fe23491237c08822dec110911e893d0a8c4f6777478bc360934b82910ff85d5d995083bba2987a67399eac427d145d546a40b9f6ff14ac488ec130fc6850a27af9544ae15ffffffffffffffff1243513f000000000000000a3621c56cea8d20fa911a0c41db6ebe8cac64f17679141d54b34bbc9963ac4f4bb3309603f1d4ab966203861b5b15a841f2b575a8bd0d78248ebe4d9a80002695104f674c2431dca141fae269cab70e9a66f3c3a9a63e9639e1f59c0ede26c6b5d74b078a5e15c31634e5ae098ce9ee70771aaa18119a867e14ffd9f9db2a7869d85864056526f889af43a6056080572286522449df466c632b3570243f989cce7cd9f465e41e610c20d80421d653a5520000008213b704c7fb082ff27590678ef9f190bae97909507041d860420c5664b27921b14dc1db8892fd32d0ad7bc946813591ad8deff4b05f60cea0da7710ac0000000000008000bea37ce0d0d4aa202f928f28381aab144a5d600025e19c907f6435f7590000008271a1f5f8528f227e79c1389dbdfffe492f21579d2c15b8c70cdb1c332d86d87341432750861ec2bc3451edca194b221cfec4603d276bbaa1dfa6d4fb8a48a76eafc9a9a0270e4c10d64cd5a62427264f2377fe763c43470833ac96c45f357cbbaba8f1b1fdcc7cbb61a7cdb9744ed7f9129aede2be21ccfdc4e9134f8684b3a4f3540a653bf796334e207dff70f1988037b2ed3aaf575c0b88d8f146684078416d59fdee5325928974d12dad99dac44c3f0008047096a44002bebc2420aed92fa9b6578b4779415d4ac01b75d5495c118045651cf41c2fc48b778efa5ea5677747430af4162b987b80c3e001cd34e5c92f76cc4c24eeb8bc4e9ac2aed9a53803ed0ca4ae3a9737d214060005ea6f1783e287b3bee96e3a726eafe2fdfaa78d1f48c13b64df07847754b8400daaa69bf5c8f4350aeae9ca1207e78283cd0b20ceb360c7e658828163e2d25c4aa348561f927e88f63aa70e73a5e69b3df3495903f06572e1e007fa55a2999f596d067312f5779e8dbfdcf3427138f3d444d2639a10477f9bec4b0bbb6e3c04be68981f392203dd0ee3ef478e16dacfc5e3e03cf7ab8e3902f1b0ff034ef655b253ca509383815b1b6fc6522d4e4fdc11a48cf42d48604675fde2b94cf00500a2690891abf8ab9c015073014d9e08d4338b8780bdecd436cf0541359bafffa45237f104b96210403b2de9efed496f423500c7872c827467cfa5c4e72730d56bd068ed211cf847535edecb7b373f78b095b68441a34cb51682a8ae4d24ad0465f3927f889b813076a882e8020f06c4c2ba1dd5cac7c18876da865d258734dd73583df292892448039ef799cf0630becdcce04579b5561dc825ab829827945e020c1f67ee615feb6243378e0610060f82da93aec92a5de203717aa49c2d284acfabe262fccfcbb2b75a2183c46eb65ca8104e1b4da7fbb77ab2fc043aead87c32ab875ee7c2e7b7019c982cd3b43eaeb1a5fb135c0c7dcee8fe6516a328032f88c042891824659e9e94265c803b35ee5f83a2b210520106b8a358b50ab7a1fa89af9c251fe5294b3d1802d5676d95f160ec97b1ad94872cb2044642c37b4a6cc6c04effc1672db7e4b68d787d9a7a508ae54b3cd7369dde50e8c77d95a3d361c040babb171607caac2a3559ad4f75465f49c0d0973716db6e00cb11db4a5fade2a57c10238e204a67737c3b42aae501b20f7694a00f16e2d0174035a2c22656dc29880acebdbe8ddbd75c2f998d8ac2dfad2ba3a504767b6b45a45957f24d758ed024b3849c11d412a2a03b4047497022d9c30e23ef4df5c89644f48bb536f7945b59d7bcddff754413d135273ea8e75f22f216c6b9990ae71806f2c00b4025c48b75c0f73cdb9a7b8fa367b50028067e7f16f4dd569d462f4f19eacdb3ed70eeebb4e8b404270638339d68c0ca3d2414442e8f3a154704b0e51bc664a137b26be719f4f7c9a5678a674dfc95df80b9ce375dd649c8c704e509bd88c8e63d8c7dd67071115c8982ba46af4d6adcc9f68a75b9397b035153faf46366e7205dd8d6f37525c1a0e94610dd94323f6c15d085197149bfd6655548cfd9c52c9711937f79abb1a124f1210465483cd3b2d78378cfb85ed82e7da0f6eb6d279f2ae455925d0f6f1ba571eba281f2a654fb39ddff3b484439ff158e7c5419e037f3e3ad038f2211f1033195563c7f93cd54b9094f226e783271e1e5a2a2c10712eab625d64931cd4ffe6738d97b9b5ef828ee9fb059fc01af0e79c1e14b1d25988c69a399567c1d93768f7971d31488b8658a20878b7c1dd7ba02fc42939dde3d4a3339a65d507dc59c51097b40517705da56e9ebf0afa53282bf86dbb58c548069ff6eb95aade7cc66d7bbef724779ca1f731b3346ff177050373d79ff7b3e7f9bc0fb8426b7a8878b90baaa039d3e3b63979ac3df6e6f4859afd50238c7547a39b60810938044ae185d2ba3e00a4e73676864ae090d0300000000000000b378dd4dd891e937c2ea5410e0513005000000000000003911fab964c271550027697b52160687461602f88df165d884b36ec2b6c25a2f33c715687e9d4afb96d6861aca47da73d6f3144345f48843dd014e5c5ad8fe995754bd9cf32fce1e31919c4b2082fb0a30b9deae84bed4b28045634073c9c58c89d9e99c81769177c6d594f88a4facfd4c735a20307c737afa2d60399473296b831dbd933d93994ba3064279b10ea0c5833f41f157ea2302993dbe433b1aa3a3766d5439020484f4113c4c859465c3b415c3432f81db8719539d5bf372aaaea1cc43a6c5cbe59758bfee2916580dac4b008e595f437491d87abed02cefcd9db53d94d02daee67918e5d678746383074c6bc1050000002f7809959bc048850613d17ca51055f2f416a44fe180d2d50c312cca7cb14a2bdc331f57a9817139a206fc76957227ffff2de20a4b8e3737fbb42913777c06376f799eba367e21f94ca598705f5dcb767d6f0900d6b0f6095e53c4c4234d0c1fbe434f6ab8f43c0013ee93b83946ee7759e89d7bdd1a32d7b311711b757fe43c06d21a35810d8fe98b27faea8aa12bc8716eefc5c97c45ac33eeec964c5214bc3a9359bdea1cccab94f15e36319cb34ebcacedb82c2ed3de5a8a8f0011e8f74e82d7f96093530e76692839d7961939adfdeeeaff19d11efcafb6d546fef271e89d6cc2389e81ff58cefcce3fbf4625a7e7de40e42e07b3c7340002000000000000f288a4510de03dab19d26285eda89156d50dd385a60333ba5bbf5d77cd7007ad1519ad5470de3dd6d6080cafccf8a97406bb6b68a1f0c4549820a73c880f475f732ae00398e8bd1f4108b7807fb33b72685ec37a2d3f766413a60459516246e5a1d998a2017aef0948a68cf255315ab80dd349e891aef595dc4d470e8ac32a308e15fc37d06aeac289c0523f483e1ff7408c6087f1ab652f2ef91d4f2b01987b0f46da034e5c3f745a7ee8101a3934c54e24b48ec0275e2d0687dc746b0827cbf652f406c6b95f2722e58c05f752ce2126596e1cd7655b904801784c416b22f73d324678e2724f43f1fe687c7e8a60c28b82b6528341b648cdd56fed7cdcbb1575912d5ecd36dea3bca0b7427d8392c6289455e8f8d2ab2242729251ae033a9e02210e62df0546a74b333a1c48f95fd54acb5741259e8c5488efeee327415cb4a51fd02c6f14c27693102a3cd84857cd6586fc5ca9a93eb0145fac0662ff86107f998a8ef7df8aa14046c55b03d3d47f88a8d60f7774a2ee08758897fb411a94b3c2fc5d5f0da42c0456ec015f08e5247d33ae2d35603ff8454c16f8342856935125102bb784ed7148b6ce431b63ee356b0c785f2f47b90e29389f22fc5b59a70efaea2bd40195af4486220d702e30bfc43c10ec23ea6283994a7dde4dcb61fea6b651fb1d62458d0741a12830052fcc460db043afe525629b40d7cee458e4cb5e930ed624806c43a006e39336d07c2b8081c128ad2706f48261f7897484c297a1a6613bc18f5a38d442768af38041efe03d152ef95ff569e76db2391f4509d7f339d92fdb4a89364949da398000000000000000d80a4fe654578376e599aff3565b1d531f30912b9945030b81ea9935fd46edb44a78f615255490a4b621501f2a9e4d24624c4dac9274118c67584f5d374755534d7f68f679c4ff516a9cc8036cbd65868fcb2bf1cb9aea4e05df72279fdb0d2b9e935c5af3cf474bed79dfc248c1f5aea4b8b32c5d295e57079d0fe662a46b7f71cd47744db86c50b704c971d90295c7b2c7439a2d78ccfa79b5fc2bff6bbf840262bf89394b4a0691953264d2700c838fa2c7b3425260f59554e502dcea39cb313b0000000000004ca7c12f45858d6284ca6270d6b2f0e58fded8a7b4a302a97bc641df07720ba2b26bbfcc807ca0abb1b44322269c21c5ec68cb068ea88067d905ea917bb03eefdaebdeabf2d0dce80997c915c8949de992587c2cb5fe36d7d3e5db21b094b8b77940b5f07722e47a08d367e5f84c96ec664b72934b99b3109af65d77e86abd6859cddf4bbae1f0930462df15fddbc48562ea3511a8065ef0075a12f14dcf6ebecd8d884836174faf1aa609e5f1ee1162dfa13bdc1fa7cfaadba85c72e9758f03a755d0be53f8d2a1dfb1c68cc164b0a0780d971a96ea2c4d4ca0398c2235980a9307b3d5bd3b01faffd0a5dbed2881a9700af561ac8c6b00000000000000f96f06817fc703729a7db6ff957697c9ede7885d94ffb0969be0daf60af93109eb1dee72e4363f51af62af6fb2a6df3bec89822a7a0b678058fa3fef86faec216eb6992162f8dcbf719c148cd2f9c55f4901203a9a8a2c3e90f3943dbc10360a1a49700d1dfbf66d69f6fbaf506c8bcce8bb0d872a02238926407a4eddd5d0fc5a752f90000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000400", 0x1000}}, 0x1006)
r8 = syz_open_dev$dri(&(0x7f00000008c0), 0xd21, 0x0)
ioctl$DRM_IOCTL_MODE_GETRESOURCES(r8, 0xc04064a0, &(0x7f00000001c0)={0x0, &(0x7f00000000c0)=[<r9=>0x0], 0x0, 0x0, 0x0, 0x1})
ioctl$DRM_IOCTL_MODE_GETCRTC(r8, 0xc06864a1, &(0x7f00000003c0)={0x0, 0x0, r9})
ioctl$DRM_IOCTL_PRIME_HANDLE_TO_FD(r0, 0xc00c642d, &(0x7f0000000080)={r5, 0x0, <r10=>0xffffffffffffffff})
ioctl$DRM_IOCTL_PRIME_FD_TO_HANDLE(r1, 0xc00c642e, &(0x7f0000000300)={0x0, 0x0, r10})

[  621.490223][T15768] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
[  621.528260][T15768] batman_adv: batadv0: Interface activated: batadv_slave_1
[  621.594658][T14884] XFS (loop2): Unmounting Filesystem a2f82aab-77f8-4286-afd4-a8f747a74bab
[  621.646772][T15768] netdevsim netdevsim0 netdevsim0: set [1, 0] type 2 family 0 port 6081 - 0
[  621.705653][T15768] netdevsim netdevsim0 netdevsim1: set [1, 0] type 2 family 0 port 6081 - 0
[  621.762373][T15768] netdevsim netdevsim0 netdevsim2: set [1, 0] type 2 family 0 port 6081 - 0
[  621.795826][T15768] netdevsim netdevsim0 netdevsim3: set [1, 0] type 2 family 0 port 6081 - 0
[  621.872716][T15853] 8021q: adding VLAN 0 to HW filter on device team0
executing program 1:
syz_read_part_table(0x5be, &(0x7f00000005c0)="$eJzs2z9o02kYB/An1SAonIuTk3VwOFwURzOoJFFRCNEu3g0KioiZIgiRCwg62AwtzVA6dimFLP0zNc3Q4WhpoXMpHXoUOnS5o10KXZqj9L29vf4B4fOBl4f3fb/J83uG3/gLfmo98U+3281ERPfS8X/d18oXntwoPSi/jMjEbxHR++cvUwc3mZT4719vpv162o+NXu707zzOttZe7N56Pd/oSfdf07oy3u478XCcuYncwtVv36vFgVruw2qxvvljZfn55Ha+3H7WaE49zT56m3KLqV5M9VPU4kt8jDdRiUq8i+op9R9pbdzZv15szby/v1foDM7dTbnSCec8av/PvUOvmvWHt6evDd+rzS6Vty4c5ir/4+0CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOD8TeQWrn77Xi0O1HIfVov1zR8ry88nt/Pl9rNGc+pp9tHblFtM9WKqn6IWX+JjvIlKVOJdVE+p/0hr487+9WJr5v39vUJncO5uypVOOOdR+3/uHXrVrD+8PX1t+F5tdqm8deEwV7l0Rg8AAAAAAAAAAAAAAAAAAAAAEZEvPLlRelB+GZGJ3yPi17//6Dk476bv3TMpdzPV9XQ+Nnq507/zONtae7F76/V84690/jWtK+PtvnMfhmP7NwAA//8DL5V5")
r0 = socket$alg(0x26, 0x5, 0x0)
bind$alg(r0, &(0x7f0000001dc0)={0x26, 'hash\x00', 0x0, 0x0, 'ghash-clmulni\x00'}, 0x58)
socketpair(0xf, 0x6, 0x90f9, &(0x7f0000000000))
setsockopt$ALG_SET_KEY(0xffffffffffffffff, 0x117, 0x1, &(0x7f0000000300), 0x0)
accept4(r0, 0x0, 0x0, 0x100800)
r1 = syz_usb_connect$hid(0x0, 0x36, &(0x7f0000000340)=ANY=[@ANYBLOB="12013f00000000407f04ffff000000000001090224000100000000090400001503000000092140000001220f00090581", @ANYRES64], 0x0)
syz_usb_control_io$hid(r1, 0x0, 0x0)
syz_usb_control_io$hid(r1, &(0x7f0000000240)={0x24, 0x0, 0x0, &(0x7f0000000540)={0x0, 0x22, 0xf, {[@local=@item_4={0x3, 0x2, 0x0, "b6954b00"}, @main=@item_4={0x3, 0x0, 0x0, "7d223e18"}, @local=@item_4]}}, 0x0}, 0x0)
r2 = syz_open_dev$hiddev(&(0x7f0000000080), 0x0, 0x0)
ioctl$HIDIOCGPHYS(r2, 0x80404812, &(0x7f0000000000))

[  621.966320][    T7] bridge0: port 1(bridge_slave_0) entered blocking state
[  621.966409][    T7] bridge0: port 1(bridge_slave_0) entered forwarding state
executing program 0:
r0 = socket$nl_netfilter(0x10, 0x3, 0xc)
sendmsg$IPCTNL_MSG_EXP_DELETE(r0, &(0x7f0000000240)={0x0, 0x0, &(0x7f0000000200)={&(0x7f0000000040)={0x38, 0x2, 0x2, 0x5, 0x0, 0x0, {0x2}, [@CTA_EXPECT_TUPLE={0x24, 0x2, 0x0, 0x1, [@CTA_TUPLE_PROTO={0xc, 0x2, 0x0, 0x1, {0x5, 0x1, 0x1}}, @CTA_TUPLE_IP={0x14, 0x1, 0x0, 0x1, @ipv4={{0x8, 0x1, @private}, {0x8, 0x2, @loopback}}}]}]}, 0x38}}, 0x0)
r1 = socket$nl_netfilter(0x10, 0x3, 0xc)
syz_init_net_socket$bt_l2cap(0x1f, 0x1, 0x3)
r2 = syz_init_net_socket$bt_l2cap(0x1f, 0x1, 0x3)
bind$bt_l2cap(r2, &(0x7f00000000c0)={0x1f, 0x7, @none}, 0xe)
connect$bt_l2cap(r2, &(0x7f0000000000)={0x1f, 0x0, @none}, 0xe)
r3 = syz_init_net_socket$bt_l2cap(0x1f, 0x1, 0x3)
bind$bt_l2cap(r3, &(0x7f00000000c0)={0x1f, 0x7, @none}, 0xe)
sendmsg$NFT_BATCH(r1, &(0x7f000000c2c0)={0x0, 0x0, &(0x7f0000000200)={&(0x7f00000000c0)=ANY=[@ANYBLOB], 0x7c}}, 0x0)
socketpair$unix(0x1, 0x0, 0x0, 0x0)
socket$inet(0x2, 0x0, 0x0)
setsockopt$sock_int(0xffffffffffffffff, 0x1, 0x0, 0x0, 0x0)
bind$inet(0xffffffffffffffff, 0x0, 0x0)
r4 = socket$inet(0x2, 0x0, 0x0)
setsockopt$sock_int(0xffffffffffffffff, 0x1, 0x0, &(0x7f0000000040)=0x8, 0x4)
bind$inet(r4, &(0x7f0000000200)={0x2, 0x4e20, @remote}, 0x10)
syz_emit_ethernet(0x32, &(0x7f0000000180)={@local, @empty, @val={@val={0x88a8, 0x0, 0x1, 0x3}, {0x8100, 0x0, 0x1, 0x2}}, {@ipv4={0x800, @udp={{0x5, 0x4, 0x0, 0x0, 0x1c, 0x65, 0x0, 0x0, 0x11, 0x0, @dev, @local}, {0x0, 0x4e20, 0x8}}}}}, 0x0)
socket$inet_udp(0x2, 0x2, 0x0)
r5 = socket$rxrpc(0x21, 0x2, 0xa)
ioctl$int_in(r5, 0x5452, &(0x7f0000000080)=0xfffffffffffffffe)
setsockopt$sock_int(r5, 0x1, 0x20, &(0x7f0000001780), 0x4)

[  622.026567][    T8] bridge0: port 2(bridge_slave_1) entered blocking state
[  622.026681][    T8] bridge0: port 2(bridge_slave_1) entered forwarding state
[  622.112393][    T7] wlan0: Created IBSS using preconfigured BSSID 50:50:50:50:50:50
[  622.112416][    T7] wlan0: Creating new IBSS network, BSSID 50:50:50:50:50:50
[  622.221470][T15853] hsr0: Slave B (hsr_slave_1) is not up; please bring it up to get a fully working HSR network
[  622.245912][    T7] wlan1: Created IBSS using preconfigured BSSID 50:50:50:50:50:50
[  622.245938][    T7] wlan1: Creating new IBSS network, BSSID 50:50:50:50:50:50
[  622.291608][T16069] loop1: detected capacity change from 0 to 2048
[  622.704872][T14650] usb 2-1: new high-speed USB device number 18 using dummy_hcd
executing program 0:
r0 = openat$vhost_vsock(0xffffffffffffff9c, &(0x7f0000000100), 0x2, 0x0)
ioctl$VHOST_SET_OWNER(r0, 0xaf01, 0x0)
ioctl$VHOST_SET_VRING_ADDR(r0, 0x4028af11, &(0x7f0000000300)={0x1, 0x0, 0x0, &(0x7f0000001600)=""/54, 0x0})
ioctl$VHOST_SET_MEM_TABLE(r0, 0x4008af03, &(0x7f0000000140))
ioctl$VHOST_SET_VRING_ADDR(r0, 0x4028af11, &(0x7f0000000280)={0x0, 0x0, 0x0, &(0x7f0000000340)=""/185, &(0x7f0000000140)=""/91})
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f0000000180)={&(0x7f0000000140)='kmem_cache_free\x00'}, 0x10)
ioctl$VHOST_VSOCK_SET_RUNNING(r0, 0x4004af61, &(0x7f00000000c0)=0x1)
ioctl$VHOST_VSOCK_SET_GUEST_CID(r0, 0x4008af60, &(0x7f0000000040)={@my=0x1})
r1 = socket$vsock_stream(0x28, 0x1, 0x0)
connect$vsock_stream(r1, &(0x7f0000000400)={0x28, 0x0, 0x0, @my=0x1}, 0x10)
ioctl$VHOST_SET_VRING_ADDR(r0, 0x4028af11, &(0x7f00000001c0)={0x0, 0x0, 0x0, 0x0, 0x0})
ioctl$VHOST_VSOCK_SET_RUNNING(r0, 0x4004af61, &(0x7f0000000000)=0x1)

[  622.848991][T15853] 8021q: adding VLAN 0 to HW filter on device batadv0
executing program 3:
r0 = openat$vhost_vsock(0xffffffffffffff9c, &(0x7f0000000100), 0x2, 0x0)
ioctl$VHOST_SET_OWNER(r0, 0xaf01, 0x0)
ioctl$VHOST_SET_VRING_ADDR(r0, 0x4028af11, &(0x7f0000000300)={0x1, 0x0, 0x0, &(0x7f0000001600)=""/54, 0x0})
ioctl$VHOST_SET_MEM_TABLE(r0, 0x4008af03, &(0x7f0000000140))
ioctl$VHOST_SET_VRING_ADDR(r0, 0x4028af11, &(0x7f0000000280)={0x0, 0x0, 0x0, &(0x7f0000000340)=""/185, &(0x7f0000000140)=""/91})
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f0000000180)={&(0x7f0000000140)='kmem_cache_free\x00'}, 0x10)
ioctl$VHOST_VSOCK_SET_RUNNING(r0, 0x4004af61, &(0x7f00000000c0)=0x1)
ioctl$VHOST_VSOCK_SET_GUEST_CID(r0, 0x4008af60, &(0x7f0000000040)={@my=0x1})
r1 = socket$vsock_stream(0x28, 0x1, 0x0)
connect$vsock_stream(r1, &(0x7f0000000400)={0x28, 0x0, 0x0, @my=0x1}, 0x10)
ioctl$VHOST_SET_VRING_ADDR(r0, 0x4028af11, &(0x7f00000001c0)={0x0, 0x0, 0x0, 0x0, 0x0})
ioctl$VHOST_VSOCK_SET_RUNNING(r0, 0x4004af61, &(0x7f0000000000)=0x1)

[  623.065560][T14650] usb 2-1: config 0 interface 0 altsetting 0 endpoint 0x81 has an invalid bInterval 255, changing to 11
[  623.090739][T14650] usb 2-1: config 0 interface 0 altsetting 0 endpoint 0x81 has invalid maxpacket 59391, setting to 1024
[  623.116045][T14650] usb 2-1: config 0 interface 0 altsetting 0 has 1 endpoint descriptor, different from the interface descriptor's value: 21
[  623.142638][T14650] usb 2-1: New USB device found, idVendor=047f, idProduct=ffff, bcdDevice= 0.00
[  623.157833][T14650] usb 2-1: New USB device strings: Mfr=0, Product=0, SerialNumber=0
[  623.183671][T14650] usb 2-1: config 0 descriptor??
[  623.217406][T16076] raw-gadget.0 gadget.1: fail, usb_ep_enable returned -22
executing program 2:
r0 = openat$binderfs(0xffffffffffffff9c, &(0x7f00000000c0)='./binderfs/binder0\x00', 0x0, 0x0)
ioctl$BINDER_SET_CONTEXT_MGR_EXT(r0, 0x4018620d, &(0x7f0000000140))
r1 = openat$binderfs(0xffffffffffffff9c, &(0x7f0000000180)='./binderfs/binder0\x00', 0x0, 0x0)
ioctl$BINDER_WRITE_READ(r1, 0xc0306201, &(0x7f0000000080)={0x8, 0x0, &(0x7f0000000400)=[@increfs], 0x0, 0x0, 0x0})
r2 = dup3(r1, r0, 0x0)
r3 = openat$binderfs(0xffffffffffffff9c, &(0x7f0000000040)='./binderfs/binder0\x00', 0x0, 0x0)
mmap$binder(&(0x7f0000ffe000/0x1000)=nil, 0x1000, 0x1, 0x11, r3, 0x0)
ioctl$BINDER_SET_CONTEXT_MGR_EXT(r3, 0x4018620d, &(0x7f0000000040))
ioctl$BINDER_WRITE_READ(r2, 0xc0306201, &(0x7f00000003c0)={0x8, 0x0, &(0x7f0000000000)=[@acquire], 0x0, 0x0, 0x0})
ioctl$BINDER_WRITE_READ(r2, 0xc0306201, &(0x7f00000001c0)={0x4c, 0x0, &(0x7f0000000740)=[@transaction_sg={0x40486311, {0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x50, 0x18, &(0x7f0000000240)={@flat=@weak_binder, @flat, @fda={0x66646185, 0x0, 0xfffffffffffffffc}}, &(0x7f0000000200)={0x0, 0x18, 0x30}}}], 0x0, 0x0, 0x0})

executing program 2:
r0 = openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000140)='blkio.bfq.io_service_bytes\x00', 0x275a, 0x0)
write$cgroup_int(r0, &(0x7f0000000000), 0xffffff6a)
r1 = bpf$MAP_CREATE(0x0, &(0x7f00000009c0)=@base={0xa, 0x4, 0xfff, 0x7}, 0x48)
bpf$MAP_UPDATE_ELEM_TAIL_CALL(0x2, &(0x7f0000000180)={{r1, <r2=>0xffffffffffffffff}, &(0x7f0000000040), &(0x7f0000000080)}, 0x20)
r3 = bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x0, 0xc, &(0x7f00000001c0)=ANY=[@ANYBLOB="1800000000000000000000000000000018110000", @ANYRES32=r1, @ANYBLOB="0000000000000000b7080000000000007b8af8ff00000000bfa2000000000000ada10000f8ffffffb703000008000000b704000000000000850000000100000095"], 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x9, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
r4 = userfaultfd(0x801)
ioctl$UFFDIO_REGISTER(r4, 0xc020aa00, &(0x7f0000000100)={{&(0x7f00000e2000/0xc00000)=nil, 0xc00000}, 0x2})
ioctl$UFFDIO_COPY(r4, 0xc028aa03, &(0x7f0000000040)={&(0x7f0000566000/0x1000)=nil, &(0x7f00001b8000/0x2000)=nil, 0x1000})
r5 = bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x11, 0xc, &(0x7f0000000440)=ANY=[], &(0x7f0000000240)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f0000000080)={&(0x7f0000000000)='jbd2_update_log_tail\x00', r5}, 0x10)
r6 = bpf$PROG_LOAD(0x5, &(0x7f00000005c0)={0xe, 0xc, &(0x7f0000000a40)=ANY=[@ANYRES8=r2, @ANYRES16=r4, @ANYRES32=r2, @ANYBLOB="728e2fdcef42e1865b881085a278521ab8b7da2b30008fccdccc22d54a527ece2fd76975c14cf3249463805f4d85d679886dbf0dcf485c14ade971f55a5d36540ba385169c70ca6c80aa563e015a77ed406366654de5ef4cea3e9aa722e320083226e4eba12d1da584e2c910a5f179711770cc11e7045e4ddd4526bcdd14892da50c2e419fdaa85811906cf047af92d941152e2601ed0603360921471ba88189ba072609f861d5fea7336627d1030020b5bd2e964d46117c319f2d179f6adc4fbbe6f234196ccccb24f8403fdd7b48bc9547dcabc39dd40fd1b40512b32d51499f8cbe18d4406b49178f85666d22caf25e50d8bc538f884d1277d5ffbe5fa858dc065e8720b08025df6f273eedda466ac7782b68d1423128f5bc319b6fcd0addc7afe2a298339bdae736cc9f0f6cae4d144647029308c57c7498bf2acd6029e94f68a2401f1b2976dced592a21d692b2de6815207b8ebdcd7e237d16826879b297ee2019f78c660d5f3d8192dfb3c5c36ed07e621d30577ea7697c9541596d44ba76c3d18ce82ca7bdf2405969d52ced89433dcd8181f051e6b25ba1e3353c82613c7dad26f7c3fc844e0b6e7fa3b40c3171059dd2ce2cb2031aa7b392aa366d4f43010905ac467043aa33830ef139923bb552ba70a1a6cb70cda85005edd0d8a46f8e478977efff47d6919ca7268bfbccc105527442e5006f9f6fd73455b6ced8413e7e00cb50a53f69ddc4c2f0ad92d29ee140dc1f216d3cfcf6e15f0fb5e1a2b63a0cec3557057e674501db50834d6112433e5cb0b2908e5c9ca356c507f5e7cb68ca66264737cdeccaa043e6305a5b6ddc4561631c0169c003531399ce04400e4505635c1418558fa8208ed48231697219511a865943da8112cce55d81f49bd8463faf1154ece127c9ca1a17d3f5b17983921ae8fdda902fe79bb79f2a38900f5ada3e4cee70fb3df15cfc5b237ce6c7a1ca921543ad3a1ef62e529fabe732165ca6cbf074b194cd2b4ca40b1c4dde1b54e90e64fa23b669661197981fde9e69f6f19419f9b85bddbdf0ff97c611edd3969034907b2509691eac4528af4502f2cafdb449418d33d6c640db35766b8c06d88bc5124882446c807c2f9f406878c5d2faada8ea45657c3bd35ca7cb4b287e62fdaac14528ba8379f92f2d9922d9202b177ec7f9ca2013c309c520b86645c088bb5aef735aafa2eb8900ec3e0d60b9f4fcf6e189fc7191fef12d5903957d6c77164894840ad5872a17ed98b24ae04c15b284b6614079a620213893ab963ae2dbd948748ec985a152972b4401225e53baa2ae435fdac8ea5a0872495208a0a630d668fc196c94785373c5750dba6a06e19856f923a2eabcb1d5e117631ab8b0797ad7236e1b1a11626ca51150d6c3a1ede0d23b0cb716f7c3d0e7c485a821dc367873856ae06bb77ea0263c1a284d6b80bc87f88cff7415d89e50f935e1b7078f9ccce1fb45a7da8959ea11a3c5ae8e10de380b828b2d78ef8f6e68327b1ecb7f439b54745b120ecd41c12c7f70bab7c5ec7599c18dff4c1f211fba2865e3df739f5a64c7696a8febf75f7bef90a8843e8886aa94b3c38c67ae79ae7e11ab42fad11b174ec5f867725d00e23aa54cb878634c9f9a02711a88066870e6135c238a71623747ef9d154977e740889362a2ad41ff8fac5bb55042967d5c9e5c903a991b06cb45c99acc3d6da1404e9316e6ab94327d156ffc3c99e24848a6762d8458fc1faf3cfd24fc889633630bfef3fef0288c2b0f4f42e4db7d8378070150473407c9cf169ce7fd927a7012fc16b87cb675c462f6661e5c147afb49b900f0ef3513d1cba5c71e6a432a3efce067f714ad5b8c40929012d2272d65065f81e103771e42322f38f4948a87278d46d1e415bd145c950ccf39d0fecdd8873d6d435147fa7df0bfcaf71ef8644acf002a57addc27e99cf2fb4030d0c62cd5e77b96810f049ace2cd91f4309964db916f7d67e3ca87a065db441343bce05cc2e6224aeb5222591c75486eb13b8330193bf34873b08385c026703601f0f989fa7ce53ea5d073073e95bfda1d94282bc69fe1685378ffd8fc7b65a99bd6ac6a5d5ccff8dfcf328b788eaf62754867afa9287c24236dcb280f0b6a3451ec129dff946e1ced7389c1af595f0957c06c1859b65540aeae24a28a9de87410505c4c21a9dbde9521f71ddce8ade71d0d9f009032407d1888c0df56d9084d0402441a1169818718e847ffb5bada1743fcd3fb5dd2323cee44a5a4eea452fb864724bad3568ad1b8d319ac7767787b7702509f2af8bd8c40dcef209f033dfcfbc495e7fb1b731e74aa808e5e199d6c98abad8cf9b9509a75f480f1d5959520ed277fe803534c356c1d8fdee626fc30e76fcfa853ce81aea9a2abce61fc7a0a60d33725b67779ea727966d00c66cf7ee587e8b872f4f539273e4b2c526ade8654f53f001cd1440115652a74c55c01dccf7be4d004a218478f14893c3bafa057f2dbcf7600eeeab4db39914fa708dccedbc0601b2725be88e10d7c84975abe5332bf9625fe22c9fee26f0ad8ff144aac4aea74513553183697d859d864ccbc777541921977f30a85fcea73c49f2918d0c6673874d9f099709991bb08e4b9e917cf1c24546b62d6a57d5ad1970ebd143c232d48448c4eee464905193912d94d49b326c6ec3f39f7a0dd8df9a98d10f9e22f9fa453ee7a9cbdf43d7e99b75f36cfdf6efc138517c9981c5a27a3f554eeddc96fa044551194a806b1e6e09be9b3fc2dc4e8438f2803a61e4171b7bb116e5990a57037386bf257bcf10325ffb069dc7b584547203c6d062960db2df9f45f0f1fc9d0c07f9a4927dbad159040196f5599afc8b7b636fd03a9b17da5a1840e5193761be8b204376e755ecf6166173eeebfd54a5a881c6464696414ab2a5734dbe75aeb6cb5ef8b1d77d238075454bdd682f754c1be055bf805da63c257142f21bfecf14b31e4273df3c81282cff96d7acce9052819480d86e413636a6243c340d83b248e1ac0b37543a20d6c34f721348c7f7969ee581d73784012f621b0c06a575237671e7fb71029ae5d4072855dfde473b9c5bd7ff1a5a64c2d244481667acca36a49f5b744b7dcb20f165858507524ee1a73aadff35d7b205e5e4814553b0e7e54133c3ca454730d7210baf91e5a2e369d7b42ab7a76f24d7f613f9d1cf27828e54ef080c6d30aba62a0c39f154c369fa1d423cbcfa5456b7bfbc74c5a56b559481c7647d596b6557fefa22b8e6f34daabd2602bfea9d7dc3edbc835961466a88dbd5f8d459b92a4806715f8dd99c1166af83e09f0a08292570d5356317d5277d75973d65cdb1c8f069f61f76c120d8f62f23a2ca8f2779507b98bacc8493b2d043c5dd7d0fe8450a7fac52096f5f07e6122a0d4cf95d45e7afc708f937c2f00d0becd069ea55bc21887b2de3845abf97baf6a28f5a40aad62ec699b6624652cf893b656e08b47615511de3d993596e107c5bccc6cb202be590dd37c8483926d32a6c289263c5294596137856e1851d55a835d33dd81d26ca6ff31a4db4df9d28a8be5df697ea470d726b0666cfc61644c6a56ca18e33d226e6805b27ceeabd6d3f6e5c863c6672c4c17d57b48881bad9cd74489edf3e8380d3af100852f14a501d43e5273bb9aeaf23e8c3202117cbbefbdf9cc937f0c6dd28a6b7507fd5391e6ea828721dc4d98329726c2abcb2d1b2f9d9060d9f69c8a34b82360590f9819681506618b1e5136f67dd0ba9b881e75779c58b23c3a52990bc241f9fc8e50dbdb27123bf237781c55cf513e66266373c28eb4190e948fcf847f9be20ff8229d44bd838166f96c1d2032e5d706230d7a5511dbc3edd4aeaacbc755917e7160cb7f12966041b064101a9df504a111031bd7110ed00c9e8c759a8b21f7ffc57a894c7903045407202fad29848fa2cfc1a39847fbd7751fbad1a52ba816e1299fcbbe32119b71e5a53c48b6b0662791dcc65a8ed6d915eef6b58a842c3aa657067fb0d903e8de61015a58c8241f6aa355a210448fa8c976091a4c31cba9347a3a51fae03ec09f9e296f1e961980b14e8d05760aa6423c7737b983f9e3811961247537a5d575f7904c1c69d6d3a1df8dda33ebc841051b62ea9012cea366df0220ac32d719ae5dcedee30011cb2f93cda4bbc4192102ec74d9cf29b92592bbb89e4add366500f42b23865ef66708040d77959f8eda2c83de8e73d6bbdfbe10414011b6b2e9acc2623546a580e7ec977effc1ee1ff75606260edf0c8b1d9870d011d3ca94279d856860950d5d696a3d9bbee638a6a1f8b86eb4931c16c4eab407fcba375eaeec62bc710fe38369414c781a97916b0e8e5d84a3fe4a1c2334e9ca0f0f6d2d07fd1578835026b2199a53083c61031e1ce17ab0cdb8598a7d0f6d5485d02e0613e9277df6d030fc983895a5ee86bc51aa47a3dcc087d72458867f6d25610c6bc31a18939373c169653c09350ec14c7c3fc369dfc859476ae768d0e432dc081a2ab4c0a64decce9ef0a5784bbe105a2c93bd1d5a3ca16d6b86d31cf76f9ba6569052df2a0d0c66507bc16dd8d3cdd87d974f0790a5683e7266c0079c26dfbaa5e0654ae51574e1a7767b363ec6c7ae0f7525d7150b3118e78ae47ae84acae9005be98d7e4264ae6dc983bee443d4628ebd36320527f504993f795260290393bc2808f2148bd4c601eddb0dc18241cc13228cb101673cd74924e7c2bd3389ba27db503eb194be8c3f10d445fcd5d6206c0d149b91fe1ddb58aa095fcd9178da061270f8aae07ad1ee1a1fcf2f081e2829ed9908d25f9c0be913795235719cc8dded2c3d4919094e878a70284c338fefd344e9091f591e07fda41b830fb4bf9a40650e247b3a11116b8a421c2696532087c2f43ac9b08a1e9a48352fb29db8f088fd334b46c95b4776ec4811a9fcd5965ca8ccca16e3910649d18522825e1b63bde39edf43ad1f3f1224365dd1d012a7fbab0bc825752833851e457d56db099eb7adc2f4b6081b52e4171ea21fa41ee41a03385e574d6c1dc400754c5d2f211ac79fb151559b86eb7b914386ca05c8827de8bbe770985290a5b00e1c5dd338f4b5bfe4fef6580ccdbf35bc56b28f21a9b17dd1764d90a149a9d781b467d0a07a5809928d0c36fb7b44b2e7a51ea3ca1f8c0ecadfad4e0c91a6c8de27bbe94f7cc706405579e2431f653a6ff17cdd0307c75c4ab0d137531571cc743a275b90acf7d05a519c6f7fd02187f723bf70b7cda731efcef22383ab8e7ae7a69206c4593470ea6221a9f186b6c2eddb0e495a0aaad091001bde908f900d5bb5470af9316976b1606d8ab50a7b75daca21439a9793715d7ea7ace48a267b052a80bdd83cd2b06bb2161243c7343a96913b6725362274cb1d31676576e9b7340601ab4a65846ce2626b53a3bc89956e5e101b079eb2069741f6bdda09423b98efada9b06e72d32390fce57a0a0720e63ce315713869db9709fa2770f448a3a094918d6822059b0b5fb8a23f0f032d9676083c333f378e3b97a4f13b84babe0557de1247864794f0ef5b82040e8f71d69fba0da5529f43c751bcb6b98c445cfd1d2506873ad3278b0c459fc392365602711ffd8c0caa1c7bfc4fba4ad87a3ae7b4b5385acde0182a9aaf7d0561b5ae4a06aea02eee36dd79ccc1cda5eaaa2025134cab0227f7d70dda29151d181a1025a7e8c6fadc76427fd0b97b92a2ae8708ea7ee0edeb0ca1a5c8a8b8be500468872bb0e3de600fc6eb2562a020de1f695a593ee467ae2365b00", @ANYRESDEC=r2, @ANYRESHEX=r3, @ANYRESDEC=r5, @ANYRESOCT=r2, @ANYRES8], &(0x7f0000000240)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f0000000540)={&(0x7f0000000140)='sched_switch\x00', r6}, 0x10)
fallocate(r0, 0x10, 0x1000000, 0x2c2)
r7 = fsopen(&(0x7f0000000040)='sysfs\x00', 0x0)
fsconfig$FSCONFIG_CMD_CREATE(r7, 0x6, 0x0, 0x0, 0x0)
r8 = fsmount(r7, 0x0, 0x1)
fchdir(r8)
creat(&(0x7f00000000c0)='./file0\x00', 0x0)
creat(&(0x7f0000000000)='./file0\x00', 0x0)
futex_waitv(&(0x7f0000000380)=[{0x0, &(0x7f0000000280)=0x9, 0x82}, {0xfffffffffffffffa, 0x0, 0x82}, {0x8000000000000000, &(0x7f0000000300)=0x7, 0x2}, {0x8000000000000000, &(0x7f0000000340)=0x7, 0x82}], 0x4, 0x0, &(0x7f0000000400)={0x0, 0x3938700}, 0x1)
ioctl$FIBMAP(r0, 0x1, &(0x7f0000000080))

[  623.518387][T15853] veth0_vlan: entered promiscuous mode
[  623.553894][T15853] veth1_vlan: entered promiscuous mode
[  623.659574][T15853] veth0_macvtap: entered promiscuous mode
[  623.682631][T14650] plantronics 0003:047F:FFFF.0008: unknown main item tag 0x0
[  623.697483][T15853] veth1_macvtap: entered promiscuous mode
[  623.719822][T14650] plantronics 0003:047F:FFFF.0008: No inputs registered, leaving
executing program 0:
r0 = socket$nl_route(0x10, 0x3, 0x0)
sendmsg$nl_route(r0, &(0x7f0000000080)={0x0, 0x0, &(0x7f0000000000)={&(0x7f0000000140)=@newlink={0x40, 0x10, 0x581, 0x0, 0x0, {}, [@IFLA_LINKINFO={0x20, 0x12, 0x0, 0x1, @bridge={{0xb}, {0x10, 0x2, 0x0, 0x1, [@IFLA_BR_MCAST_QUERIER_INTVL={0xc}]}}}]}, 0x40}}, 0x0)
r1 = socket$nl_generic(0x10, 0x3, 0x10)
r2 = socket$inet6(0xa, 0x3, 0x88)
bind$inet6(r2, &(0x7f0000000000)={0xa, 0x0, 0x0, @mcast2, 0xa}, 0x1c)
setsockopt$SO_BINDTODEVICE(r2, 0x1, 0x19, 0x0, 0x0)
syz_emit_ethernet(0x83, &(0x7f0000000040)=ANY=[@ANYBLOB="aaaaaaaaaaaaaaaaf9ff030486dd601b8b97004d88c19e9ace00000000000000002100000002ff020000000000000000000000000001"], 0x0)
r3 = syz_genetlink_get_family_id$tipc(&(0x7f0000000440), 0xffffffffffffffff)
prlimit64(0x0, 0xe, &(0x7f0000000140)={0x8}, 0x0)
sched_setscheduler(0x0, 0x1, &(0x7f0000000080)=0x7)
r4 = socket(0x840000000002, 0x3, 0xfa)
connect$inet(r4, &(0x7f0000000140)={0x2, 0x0, @remote}, 0x10)
sendmmsg$inet(r4, &(0x7f0000005240), 0x4000095, 0x0)
r5 = socket$inet6_tcp(0xa, 0x1, 0x0)
listen(r5, 0x0)
listen(r5, 0x0)
r6 = openat$kvm(0xffffffffffffff9c, &(0x7f0000000000), 0x0, 0x0)
socket$nl_route(0x10, 0x3, 0x0)
r7 = ioctl$KVM_CREATE_VM(r6, 0xae01, 0x0)
ioctl$KVM_CREATE_IRQCHIP(r7, 0xae60)
r8 = ioctl$KVM_CREATE_VCPU(r7, 0xae41, 0x0)
sendto$inet6(0xffffffffffffffff, &(0x7f0000000080)="44f9b108b1cdc885c9c533d21f474bec8b", 0x11, 0x0, 0x0, 0x0)
ioctl$KVM_CAP_HYPERV_SYNIC2(r8, 0x4068aea3, &(0x7f00000008c0))
ioctl$KVM_SET_MSRS(r8, 0x4008ae89, &(0x7f0000000080)=ANY=[@ANYBLOB="010000000000000090000040"])
sendmsg$TIPC_CMD_SHOW_LINK_STATS(r1, &(0x7f0000000500)={0x0, 0x0, &(0x7f00000004c0)={&(0x7f0000000480)={0x1c, r3, 0x1, 0x0, 0x0, {{}, {0x0, 0x410c}, {0x14, 0x14, 'broadcast-link\x00'}}}, 0x30}}, 0x0)

[  623.785528][T15853] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3e) already exists on: batadv_slave_0
[  623.805077][T14650] plantronics 0003:047F:FFFF.0008: hiddev0,hidraw0: USB HID v0.40 Device [HID 047f:ffff] on usb-dummy_hcd.1-1/input0
[  623.832505][T15853] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
[  623.858000][T15853] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3e) already exists on: batadv_slave_0
[  623.890571][T15853] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
[  623.930845][T15853] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3e) already exists on: batadv_slave_0
[  623.975091][T15853] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
[  624.005732][T15853] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3e) already exists on: batadv_slave_0
[  624.024232][T15853] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
[  624.049484][  T927] usb 2-1: USB disconnect, device number 18
[  624.070636][T15853] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3e) already exists on: batadv_slave_0
[  624.103447][T15853] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
[  624.148186][T15853] batman_adv: batadv0: Interface activated: batadv_slave_0
executing program 3:
r0 = syz_init_net_socket$x25(0x9, 0x5, 0x0)
r1 = socket$l2tp(0x2, 0x2, 0x73)
bind$l2tp(r1, &(0x7f0000000300)={0x2, 0x0, @broadcast}, 0x10)
connect$inet(r1, &(0x7f0000000200)={0x2, 0x0, @local}, 0x10)
connect$inet(r1, &(0x7f0000000000)={0x2, 0x4e21, @private=0xa010101}, 0x10)
getsockopt$inet_int(r1, 0x0, 0x22, &(0x7f0000000040), &(0x7f0000000080)=0x4)
sendmmsg$inet(r1, &(0x7f0000000900)=[{{0x0, 0xd, 0x0}}], 0x40000cf, 0x0)
r2 = socket$inet_udp(0x2, 0x2, 0x0)
getsockopt$SO_BINDTODEVICE(r0, 0x1, 0x19, &(0x7f0000000480), 0x10)
setsockopt$inet_mreqsrc(r2, 0x0, 0x27, &(0x7f0000000100)={@multicast2, @dev, @multicast1}, 0xc)
setsockopt$IP_VS_SO_SET_STARTDAEMON(r2, 0x0, 0x48b, &(0x7f0000000440)={0x2, 'macvtap0\x00'}, 0x18)
r3 = openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000300)='cpuacct.usage_percpu_user\x00', 0x275a, 0x0)
write$binfmt_script(r3, 0x0, 0x208e24b)
mmap(&(0x7f0000000000/0xb36000)=nil, 0xb36000, 0x0, 0x28011, r3, 0x0)
accept4$inet6(r3, &(0x7f0000000180)={0xa, 0x0, 0x0, @mcast2}, &(0x7f00000001c0)=0x1c, 0x80000)
sendto$inet6(r3, &(0x7f0000000240), 0x0, 0x20004841, 0x0, 0x0)
getsockopt$inet_buf(r1, 0x0, 0x10, 0x0, &(0x7f0000000140))

[  624.281291][T15853] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3f) already exists on: batadv_slave_1
[  624.327077][T15853] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
[  624.352064][T15853] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3f) already exists on: batadv_slave_1
[  624.403254][T15853] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
[  624.444885][T15853] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3f) already exists on: batadv_slave_1
[  624.483606][T15853] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
[  624.521021][T15853] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3f) already exists on: batadv_slave_1
[  624.599170][ T1246] ieee802154 phy0 wpan0: encryption failed: -22
[  624.605729][ T1246] ieee802154 phy1 wpan1: encryption failed: -22
[  624.613749][T15853] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
[  624.629442][T15853] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3f) already exists on: batadv_slave_1
executing program 1:
fsopen(0x0, 0x0)
r0 = bpf$PROG_LOAD(0x5, &(0x7f0000008000)={0x15, 0x3, &(0x7f0000001300)=ANY=[@ANYBLOB="b700000000000000070000000900000095000000000000001e5286574356940658273ad1326fc65be4b1037a74cfb5af100fc4e94d123d9b22a7561b8850821bc1f80000a3e3b79b0d96030000000000000004bfffe68fe46421a161eedd1a5cee316f68f7617859f06c8efd5da6abe446649c322209b1af93c6c999058168ad0a70992124d19c7c9cc22ff9a6b9a058363dd6039ab938480e8697f8715bcb18e1fd077390947ba783148e0e7b604a6c47b33c43a3ffff92ec8bbde1af40f29cfcf0836a70a2f6b1192abdf24ca363492393e1c2a3b190180c6b74c38cae7761f7f2530320bdcc7cbd97aefd846ac8f823402eea2bdeaf5e99514e64e36cad5eba82010b2d149aa72e5f070000000000000000000000002904000000003a4a01000100f0e0dbb9821d9c5402474d5866ce5eb60188d83ac741b45aeacac594cf09de9b460f48b96ae8a0ee478e46c8ca3e4c5d2b3cb4ad480100000000000000dcbf36b7e8be59ca4b46266cf75bea8a22ab71895d954dc6d28864144c73391770690a9301cbe97565d5000000000000000455355d5d55f551df82ea475a3e1ec56d000000008a3426574f4730d0fbec5b005ebb633b29ee04d6657ce7478d67cac87fdd75f3461b34a96b1b8d2434e00c488337a6a7ae59a0ba01c12809c5a0b5b80c05a5f7eac3604cb21d779f46993a29525325498f2de711c92588fcc183d26f25386e22b236d1e4b5c1289890edebe32d17159217a960051b9a274473c836cfa41a673f5f63ed6dc6bdea0796d12b15bec79a75b7da9574893726a6e65c5009ec8d4b533e46a9694853deed3969fe2d6a7b8a7cf38ecd3b9cb369051efddc89bcc3f4b558f4aabf7afd"], &(0x7f0000003ff6)='syzkaller\x00', 0x1, 0xc3, &(0x7f00000002c0)=""/195}, 0x48)
socketpair$unix(0x1, 0x5, 0x0, &(0x7f0000000000)={0xffffffffffffffff, <r1=>0xffffffffffffffff})
setsockopt$sock_attach_bpf(r1, 0x1, 0x34, &(0x7f00000000c0)=r0, 0x4)

[  624.664820][T15853] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
[  624.705649][T15853] batman_adv: batadv0: Interface activated: batadv_slave_1
[  624.778011][T15853] netdevsim netdevsim4 netdevsim0: set [1, 0] type 2 family 0 port 6081 - 0
[  624.846601][T15853] netdevsim netdevsim4 netdevsim1: set [1, 0] type 2 family 0 port 6081 - 0
[  624.881083][T15853] netdevsim netdevsim4 netdevsim2: set [1, 0] type 2 family 0 port 6081 - 0
executing program 1:
openat$iommufd(0xffffffffffffff9c, &(0x7f0000000000), 0x0, 0x0)
openat(0xffffffffffffff9c, &(0x7f0000000040)='.\x00', 0x0, 0x0)
openat$binder_debug(0xffffffffffffff9c, &(0x7f0000000040)='/sys/kernel/debug/binder/state\x00', 0x0, 0x0)
r0 = socket$can_raw(0x1d, 0x3, 0x1)
ioctl$ifreq_SIOCGIFINDEX_vcan(r0, 0x8933, &(0x7f0000000a00)={'vcan0\x00', <r1=>0x0})
setsockopt$SO_TIMESTAMPING(r0, 0x1, 0x25, &(0x7f0000000000)=0x3cca, 0x4)
sendmsg$can_raw(r0, &(0x7f0000000340)={&(0x7f0000000280)={0x1d, r1}, 0x10, &(0x7f0000000300)={&(0x7f00000002c0)=@can={{}, 0x0, 0x0, 0x0, 0x0, "d53495ed19ac6f39"}, 0x10}}, 0x0)
socket$igmp6(0xa, 0x3, 0x2)
pselect6(0x40, &(0x7f0000000600), 0x0, &(0x7f0000000680)={0xff}, 0x0, 0x0)

[  624.915127][T15853] netdevsim netdevsim4 netdevsim3: set [1, 0] type 2 family 0 port 6081 - 0
executing program 2:
prlimit64(0x0, 0x0, 0x0, 0x0)
close_range(0xffffffffffffffff, 0xffffffffffffffff, 0x2)
timer_create(0xfffffffffffffffc, &(0x7f0000000140)={0x0, 0x12}, &(0x7f0000001400))
timer_settime(0x0, 0x0, &(0x7f000006b000)={{0x0, 0x8}, {0x0, 0x9}}, 0x0)
syz_mount_image$vfat(&(0x7f0000003880), &(0x7f0000000000)='./file1\x00', 0x40, &(0x7f0000000180)={[{@uni_xlateno}, {@shortname_win95}, {@shortname_winnt}, {@iocharset={'iocharset', 0x3d, 'macromanian'}}, {@shortname_lower}, {@shortname_lower}, {@utf8no}, {@utf8no}, {@fat=@nfs_nostale_ro}, {@fat=@uid}, {@rodir}, {@shortname_win95}, {@shortname_winnt}, {@iocharset={'iocharset', 0x3d, 'ascii'}}, {@fat=@uid}, {@utf8}]}, 0x1, 0x2a9, &(0x7f0000000480)="$eJzs3c9KM1cYB+B3YkzSdpGsS6Gz6FrUbTdxoVDqqsVFu2mlKogJBQXBUhpdddsb6BUUCt2V3kM3vYNCt4UuhQpTJpkxxiRT82H0+/B5Nh7PnN+cP45kIfP65Xv9k4M0jq6+/TNarSRq3ejGdRKdqEXpMiZ0fwgA4E12nWXxTzaySC6JiNbylgUALNHU53+SVAd+eZp1AQDL8+lnn3+8tbu7/UmatmKn//35Xv75n38dXd86iuPoxWGsRztuIrJbo/ZOlmWDeprrxAf9wflenux/8Xtx/62/I4b5jWhHZ9g1mf9od3sjHbmTH+TreLuYv5vnN6Md/07MX/6BYntzKh8R9c7k+teiHX98FV9HLw6GixjP/91Gmh7/Vp5Ink8G53vN4bixbOUJfhwAAAAAAAAAAAAAAAAAAAAAALwQa0XtnGYM6/fkXUX9nZWb/JvVSEudyfo8o/xttcB79YEGWfxY1tdZT9M0KwaO8/V4tx7159k1AAAAAAAAAAAAAAAAAAAAvF7OLr452e/1Dk8fpVFWAyhf63/V+3Tv9Lwfcwfn0+w3x3PVimbFnWOlHJNEVC4j38QjHUt14/LirXlr/unninhrVqr1/5OuVp3P4zTKp+tkPxmdYXJvTDPGuygav969TyNOz7KHzNWYdylb6PFrzLzUXnjvjXeGjUHFmEiqFvbhX6OTK3qS+7toDE91Zny1aBTx2tTT28p7GvPiU78pUxLVOgAAAAAAAAAAAAAAAAAAYKnGL/3OuHhVGa1lzaUtCwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACe1Pj//y/QGBThBwxuxOnZM28RAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAF+C/AAAA//+zK1UG")
mount$9p_fd(0x0, &(0x7f00000001c0)='.\x00', 0x0, 0x804020, 0x0)
r0 = openat(0xffffffffffffff9c, &(0x7f00000003c0)='./file1\x00', 0x1c5002, 0x0)
ftruncate(r0, 0x0)

executing program 0:
r0 = syz_init_net_socket$x25(0x9, 0x5, 0x0)
r1 = socket$l2tp(0x2, 0x2, 0x73)
bind$l2tp(r1, &(0x7f0000000300)={0x2, 0x0, @broadcast}, 0x10)
connect$inet(r1, &(0x7f0000000200)={0x2, 0x0, @local}, 0x10)
connect$inet(r1, &(0x7f0000000000)={0x2, 0x4e21, @private=0xa010101}, 0x10)
getsockopt$inet_int(r1, 0x0, 0x22, &(0x7f0000000040), &(0x7f0000000080)=0x4)
sendmmsg$inet(r1, &(0x7f0000000900)=[{{0x0, 0xd, 0x0}}], 0x40000cf, 0x0)
r2 = socket$inet_udp(0x2, 0x2, 0x0)
getsockopt$SO_BINDTODEVICE(r0, 0x1, 0x19, &(0x7f0000000480), 0x10)
setsockopt$inet_mreqsrc(r2, 0x0, 0x27, &(0x7f0000000100)={@multicast2, @dev, @multicast1}, 0xc)
setsockopt$IP_VS_SO_SET_STARTDAEMON(r2, 0x0, 0x48b, &(0x7f0000000440)={0x2, 'macvtap0\x00'}, 0x18)
r3 = openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000300)='cpuacct.usage_percpu_user\x00', 0x275a, 0x0)
write$binfmt_script(r3, 0x0, 0x208e24b)
mmap(&(0x7f0000000000/0xb36000)=nil, 0xb36000, 0x0, 0x28011, r3, 0x0)
accept4$inet6(r3, &(0x7f0000000180)={0xa, 0x0, 0x0, @mcast2}, &(0x7f00000001c0)=0x1c, 0x80000)
sendto$inet6(r3, &(0x7f0000000240), 0x0, 0x20004841, 0x0, 0x0)
getsockopt$inet_buf(r1, 0x0, 0x10, 0x0, &(0x7f0000000140))

[  625.053055][T16124] IPVS: sync thread started: state = BACKUP, mcast_ifn = macvtap0, syncid = 0, id = 0
executing program 3:
r0 = openat$kvm(0xffffffffffffff9c, &(0x7f0000000100), 0x0, 0x0)
r1 = ioctl$KVM_CREATE_VM(r0, 0xae01, 0x0)
r2 = ioctl$KVM_CREATE_VCPU(r1, 0xae41, 0x0)
ioctl$KVM_SET_TSC_KHZ(r2, 0xaea2, 0xf6e)

[  625.344917][T16128] IPVS: sync thread started: state = BACKUP, mcast_ifn = macvtap0, syncid = 0, id = 0
[  625.375131][   T57] wlan0: Created IBSS using preconfigured BSSID 50:50:50:50:50:50
[  625.394246][   T57] wlan0: Creating new IBSS network, BSSID 50:50:50:50:50:50
executing program 0:
socket$inet6_tcp(0xa, 0x1, 0x0)
r0 = openat$pfkey(0xffffffffffffff9c, &(0x7f0000000040), 0x200000, 0x0)
r1 = openat$binderfs(0xffffffffffffff9c, &(0x7f0000000540)='./binderfs/binder0\x00', 0x0, 0x0)
ioctl$BINDER_WRITE_READ(r1, 0xc0306201, &(0x7f0000000640)={0x20, 0x0, &(0x7f0000000680)=[@request_death, @clear_death], 0x0, 0x0, 0x0})
r2 = openat$cgroup_ro(r0, &(0x7f0000000080)='blkio.bfq.io_service_bytes\x00', 0x275a, 0x0)
mmap(&(0x7f0000000000/0x3000)=nil, 0x3000, 0x1, 0x12, r2, 0x0)
socket$inet_udplite(0x2, 0x2, 0x88)
ioctl$KIOCSOUND(0xffffffffffffffff, 0x4b2f, 0x0)
mkdirat(0xffffffffffffff9c, &(0x7f00000000c0)='./file0\x00', 0x0)
mount$bind(&(0x7f00000002c0)='.\x00', &(0x7f0000000200)='./file0\x00', 0x0, 0x101091, 0x0)
mount$bind(0x0, &(0x7f0000000140)='./file0\x00', 0x0, 0x100000, 0x0)
mount$bind(&(0x7f0000000280)='./file0/../file0\x00', &(0x7f0000000080)='./file0\x00', 0x0, 0x1000, 0x0)
mount$bind(&(0x7f0000000300)='./file0\x00', &(0x7f0000000040)='./file0/file0\x00', 0x0, 0x91905a, 0x0)
mount$bind(&(0x7f0000000100)='./file0\x00', &(0x7f0000000180)='./file0\x00', 0x0, 0x112dd10, 0x0)
mkdirat$cgroup_root(0xffffffffffffff9c, &(0x7f0000000000)='./cgroup.cpu/syz1\x00', 0x1ff)
mount$fuse(0x20000000, &(0x7f0000000580)='./file0\x00', 0x0, 0x223216, 0x0)
r3 = syz_open_procfs(0x0, &(0x7f0000000100)='mountinfo\x00')
r4 = socket$inet6(0xa, 0x3, 0x88)
setsockopt$inet6_IPV6_XFRM_POLICY(r4, 0x29, 0x23, &(0x7f0000000700)={{{@in=@local, @in=@loopback, 0x4e23, 0xffff, 0x0, 0x0, 0x2}, {}, {}, 0x0, 0x0, 0x1}, {{@in=@broadcast, 0x0, 0x32}, 0x0, @in6=@loopback}}, 0xe8)
connect$inet6(r4, &(0x7f0000000000)={0xa, 0x0, 0x0, @ipv4={'\x00', '\xff\xff', @dev}}, 0x1c)
r5 = open(&(0x7f0000000a40)='./bus\x00', 0x141a42, 0x0)
sendfile(r5, r3, 0x0, 0x100801700)
bpf$PROG_LOAD(0x5, &(0x7f00002a0fb8)={0x4, 0x4, &(0x7f0000000080)=ANY=[@ANYBLOB="b70000000065ffe2690a00ff000000006d00000000000000950000000000000018100000", @ANYRES32, @ANYBLOB="000000000000000005000000000000009500000000000000"], &(0x7f0000000140)='GPL\x00', 0x2, 0x95, &(0x7f0000000180)=""/149, 0x0, 0x0, '\x00', 0x0, 0x30}, 0x90)
mkdirat(0xffffffffffffff9c, &(0x7f0000000040)='./file0\x00', 0x0)
getdents64(0xffffffffffffffff, 0x0, 0x0)

[  625.488443][   T28] wlan1: Created IBSS using preconfigured BSSID 50:50:50:50:50:50
[  625.521747][   T28] wlan1: Creating new IBSS network, BSSID 50:50:50:50:50:50
executing program 4:
r0 = fanotify_init(0x0, 0x0)
fanotify_mark(r0, 0x2, 0x8001021, 0xffffffffffffffff, &(0x7f00000003c0)='./file0\x00')
ioctl$IOMMU_VFIO_IOMMU_UNMAP_DMA(0xffffffffffffffff, 0x3b72, &(0x7f00000000c0)={0x18})
openat$tun(0xffffffffffffff9c, 0x0, 0x0, 0x0)
r1 = socket$inet_udplite(0x2, 0x2, 0x88)
getsockopt$sock_cred(0xffffffffffffffff, 0x1, 0x11, 0x0, 0x0)
setresuid(0x0, 0x0, 0xee00)
socket$kcm(0x10, 0x0, 0x4)
sendmsg$inet(r1, 0x0, 0x804)
ioctl$TUNSETIFF(0xffffffffffffffff, 0x400454ca, 0x0)
epoll_create1(0x0)
bpf$PROG_LOAD(0x5, 0x0, 0x0)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, 0x0, 0x0)
sendmsg$nl_route(0xffffffffffffffff, &(0x7f0000000140)={0x0, 0x0, &(0x7f0000000100)={&(0x7f0000000080)=ANY=[@ANYBLOB="1c0000001c00000000000000000000000a000000", @ANYRES32=0x0, @ANYBLOB="00100000"], 0x1c}}, 0x0)
r2 = openat$ptp0(0xffffffffffffff9c, &(0x7f0000000140), 0x0, 0x0)
r3 = dup(r2)
ioctl$PTP_EXTTS_REQUEST2(r3, 0xc0603d06, &(0x7f0000000040))
pipe2$9p(0x0, 0x0)
write$P9_RVERSION(0xffffffffffffffff, 0x0, 0x15)
r4 = openat$sndseq(0xffffffffffffff9c, &(0x7f0000000100), 0x0)
ioctl$SNDRV_SEQ_IOCTL_SET_PORT_INFO(r4, 0xc0a85320, &(0x7f00000003c0)={{0x80}, 'port1\x00', 0xe3, 0x1b1c07})
r5 = openat$sequencer2(0xffffffffffffff9c, &(0x7f00000000c0), 0x42b02, 0x0)
dup3(r4, r5, 0x0)

[  625.611220][T16132] loop2: detected capacity change from 0 to 256
[  625.703586][   T29] audit: type=1800 audit(1715377305.224:981): pid=16132 uid=0 auid=4294967295 ses=4294967295 subj=_ op=collect_data cause=failed(directio) comm="syz-executor.2" name="file1" dev="loop2" ino=1048773 res=0 errno=0
[  625.742597][T16132] FAT-fs (loop2): error, invalid access to FAT (entry 0x00000001)
executing program 4:
r0 = openat$fuse(0xffffffffffffff9c, &(0x7f0000002000), 0x2, 0x0)
syz_mount_image$fuse(&(0x7f0000002040), &(0x7f0000002080)='./file0\x00', 0x0, &(0x7f0000000240)=ANY=[@ANYBLOB='fd=', @ANYRESHEX=r0, @ANYBLOB=',rootmode=00000000000000000040000,user_id=', @ANYRESDEC=0x0, @ANYBLOB=',group_id=', @ANYRESDEC=0x0], 0x3e, 0x0, 0x0)
syz_fuse_handle_req(r0, &(0x7f00000080c0)="c6cfdab7e6f83fe5e44dd3a8d886a720a29cfb7e50ef99fcf38be6c3b9a9f8c9fdb7b1332c99b85247977ad2d66a577e6f0853366c7561476cb35cf07e6fc1c21d33853a21771a8835a50d941d35a4ccb511cb67ed64259c99811f0e6f176fba1e0fa45fefe030a588f0cf64895fb12a794fd0bd176a38440328d3c6c24c85f50e95c5190eb03fb04f1eb34cae287ed75c8ca8fab2c04dc1fafa14ef93e2a721a12238700dfdabd057e94e697534e1af81921756270313d22a185c146852a5e94300bc8de9904e8c6948d5d2aed05337b9572ee74b77209c6b4710e87fa6661b19283079a46f70a538d96f484b63171bdc3622fcbab6d9bafeaacd755923209c07b8c2f39c04ea713020bcd9e6f1120ea3fbc8dd0b55986c05aa0c0b13ad52f250e9505ba53a887ed7c857e0f56282d6dd5932930efe384bbb198c50aae4b9a65e6a6ccc2904a9121a28df865011c39a54fb0f890cc1f7ef5f5172754f1c2aa8e8acf8c754f22efa88ffea91f2a14133e0a7a8a06bc80d042ce1affa2ebc74b49b48169404b33c62915e54c554d10bc432ec988f7081a8690335d58d0a819d33296db1377af876d84fd557f9a2018ee91f7d39819fc72b0a9bbdd05d6efe6cc459cd42e16f955dcb1a6a2b8b2a71b3a7e1bfa82816abf8c7d3688d53decbc480eaa3821cef557290284d9c504a63768852e15b39841ef3648f14c7edab005230c7bd518f300df6ff307c0740150dddfdab1e408edb96b2e6ed612b0bc2fca570fa1813d86160a766fe6c11cdbc7a67014fa7645b4b1d3aad378bcce27aa4725ecf7675b2682cc5a15673136e7181ed5ef122017dc72df65af147dcb9ac702f8a6a2eb3f6824ba7db3c32fa4bfbf63dcd45e42a49b6edee22856fc2a43aeb6a3eea91dbd53a231b559ca7b38564853be3bdee7f820966faa916ed4fd335159328f8b727ba068b0ade0e11c9f2c2af4d5244f5d49f9c9f94105a6fe4c71112bcacf9c3dd2861d06cb3fa6b2159bc2028e513298b594ca7da60f4ed30edd7b066c23ca7d9b7d9555b47e687b43b7b5ca3210d939e34dd3d176d8b3d3d2f32f28518aa8b5169362fee4a4ede7d3d218db0ecc3de14789344df20188d907093bbf621fe67ab2a1f29221b2ec334dadc15345fc829005f4f81fc13ad0f5590742295812a7f2108cbbbc37387a7d4174592bf4f94f272306942e6c44b23e96d92911ef416b4159e81b19f267aad20c2aabf7fd285330cbf4c1bb8ac86493e0ef84de88eb7953fcf833e6cc5ebdd50b706bcc148971d24e9d3736ed66e28f75e6a1e2c9a4e2abba887b27815d2f5739fe5f8afe7240841337bfe7a69308186180fed5736fe3cbc2892cb991d0f4400d66952459c54a16448f06fd49995aa65501631d5c42e2abd8f0d890a6bbe49b384bfe27599afd536493981be5f7dbb15bfbc198fcd8ebfca182c53156742e237df31c1dca495e40cf030623a8a081e3bec3b8e5109ba05c0830ef00ff98a4419bae14762d8e0a790c1d517f1f683bb1712a6a0951f024a46efb5c2122460495fa0f4ebaae86286b8a626be2052874f947f18b0c2860ce681a33d5f4217415363fe7a6f8fca125742f03433988d88a5b8e2bf4f3079eb990b6e1ff381b7199717fb885f4f37351bf18bedbeeca351b7bfca5b791b91be0dcf8d169914c449829669e0577d1ebc4fa783d57e0c695cafae201014831a16d8fec47f22d9b79c2acc820f4dba9d1a2986731681ed1f8dd1e83bc2d491302d2f769e6b0bc47040492ffaef4267d15182adc6f5073220590d1ce89a520b6d51d6903dd54360cd7047aed76e0a6cd3c3625e67b7c1636fd627aa48f1ee6dd567730c6ec19d1634f62a77f70c64736532455f0d2ae85003e7bb32f06b480a9f7fba5e6917305fd77e38f6936e49c1a3b2a07e242ccc2f9d629d7992937a035574b3efefd515096e30058cb60cc89d8565205f15e71d805ba5d1c4f7b971918e32bd81611a574fc651bc8094f7f3aef8a3ebf95aef1c062ec66e288b1d1ee17ab75723bc46b031744a25cf055c1bc8b083313e38d0fd5d60e832ef28fbff4c93d2d2ed283575a486167c7158e08fe7094d23984bdf38cf6000db39c5d0f7db72325af909b18247d8fddd89eff8831c294d52194a11dae2339938a79ae903eb63bc6e5535796e1c0416cdad01e1493a3075930a0b3b50ad904ff760bec5c6406b10808bf13251df73b4d6fd149a378ac277ccbbfddd9536abdf5c7a8d29e128a290f0d56c9635540f4c9a3ff1d3e0e2b974b50497ebd690dc9393f8b3acfd1650627db8ab784233727f997dab536f1e993980a41f510fa0128d6bf2c8445ed1578b25a36e05f7170b9fbe8ca63e1b4a7235c27f56790c4dd38168ce26358d12b143e9dbae1d01406778250f1c77c80643016ffd4a7a6703b9c3dfa4e7b51fa1d59605d57c9712159eb34c306a988ac95eeb15c3225ccd022d2ccf5f31a81009d2a25891b83e60efe8f718d6c124202f108d23e5e6c89e269890bda8e5681315db361cdf30e4269f2cb530a188f26621a8b263f22bb385d779b3c4eebd16656451087457892e15074abb1c796f0b7f635b9496f3a17220716c449c11c0e82b67b8f1ee6a2709a20676f40f2751df3d74db503db6cb73c955ae1d6983da44de4d349004f3d9db4ba40124416a67bd18d1d9b3c1e4706ddbb2099a2ae16e99c144860d46ef66bc6844963c0563fe2cb8c4049dea32ce5656fbfec6d1aff7ef48bac92c932c9787d9e4cb0c78fc3d70f730c452c20d077b4d9ea304f1b8a2967b1e7af7f05fd35f84d633bf5095b1af53a506f6f61abc99186eba707843e9db2a18fc1c6c77dd79ab9353eaad6457245709acbe9cb381d4458eb5571fa4f4df069ae668b1df2c97f91271be5fc2040031c3980c7555af2d4186875ea4599c873ffaf47aa08c27a0580ceef6251dce4cfd6eb175a1bf36c1fd750826f4e14966e6f196b68da0a524baf86f49ce8c09430554b50a0b387c02ebd59fae9caa1054cba1304aa6732f3990ce6b7bca6b65237f0fc3c79a102e2989dcf3f884002f2efe83e25a3fb217c24c4f66e0973e7ca62483bb52c943ccfbf31324f2b7938de0555a54f47256c903ab65489906c382d7d1022f7f302b186d18b5775e042ba83b874793420a6d854aaec01e3c819d0b11b51558fb9c10b1e2ff96639fb119d90f80aa302c9a6420b4b1230d79fd1e8105259c4ebf9cc3f1eac67f15bcb9d49ae537084c96994ad08214ac07db663c1bbce6499b5665fb5a949ab3d65062467824a2065a9de2f1edc243e03ad38f0ef227519de50a3dc2e8f4a38538be5557c5de56d0110a0759fe96b0e66d20fcb6066995f77fba9c7468434a53892cf2b3f41d58e08bd2ea3b1da2a1178acf50249d77757353943cd126b511098230698782ca88d018381f233f4331d3980f72f30caf915a18794de1253734b89303f25826a80ddd75a9bdf14c6f01690833190872ca5431ab92ab3dca92595983b11de0076125059234720906641119dab9c96be9c10d60fb54267bda61fcb85a491df037cd563b229eea02cd192796d36803b04691d385471a5f68bb76afafe9df28f50dcabfefc8e2eb334bcace928b8eb8f6449116fb5a0fa4a0c51e21b8b1f99308d396db60418cb5385bdf6bce7227e514f6cbc9a9fc50b79e8b0530fd51b21679ea1c404dba52811b3c9487f670e622ac7b1ce8028eadbd882d4325663d8dc4f0960c047c5f3099c90c6256bc11e8eef6b325e0f1ed00279a695f2828762f28ecacdc726aedf42064727ec100ffa74d38d47f383946b9f856e53cb939a619f205e030a302628ffb9b2cfcc2e881e239f33844a118a4de2a5c3d6b857c5105db775a61c5d54d1d82048670e8cd2c44a032904005125eb9f999e845efba3a063e3e26b06298f28799975b51118eece2b7fec02d4b888bfb90919bec287aba71296c66dcf749efa3abcddfccee6ef80d03a1638045f18fb96131cbd9a93e657c29eb74de40f433969e1988ac335bdd9c671b5b75ce6e2440be247775f9d597b4d8523c283e774ed0987e10b88e0c5616720502149db329babc91b225359927f88e0b42f02d41a4c9e0ad7c55a0d2c52cf45da6152c0c742f661b562c3a8ecff1145cac3f63fc053e1a14fe7a57742ab709581604fabe54ff13172b5049434d12f6ed9623265af643f725efea21e2ac1b82365033b9cff4158318f40c8894d2bcffdc954fcf7068c97ca2d2b1bf19b9232b918864e3f63fd59f4c8c578821ec5083e46363d9158451c5a92b425e68081b2c7572df44658a4aae41a439c6bb4bdd2f26ff2a357fa2946e5be5cd97ba25f73bbcc6c05fa966d0aa0cf2e45f22e0021468b37d5afebbfba3233e2cd4fd64e1578be72c38891224cd6c70c4cfd146df6a8142f1493772d48650f808000000ff704e02ec121e9f43de623eff8070f88a623cd395a02b6b1ffe4ea7ae7f443dc8bdac2cfaa126d4ac9d7788dc972c88fd87d3c8758853f1882532e4ff298b466e7d198daa9015127f2937544b34aaf545f39ee00d74e0e1017a30ff2edff701d53f3a13fc61b31fe7d9032a6c4a517c7527e48c0c44a2beebc9a9f9e6f989bc6c255e05bec5ff99547658143d9eb43a1d96aa5288638b4477aa1f84c59d41194335c09d9d5d660640acb84b53520482fb200ca616e1a6f486e6da3e6721479e85d0676ba142d95ecdf1acc76a49e9bf016f951d8b95adc7e8d4317ddbb28b678135a4a9b98fb8b8b5948b682ee70e04a31f7e3c49c52a11acbb29bd8152bbb4fedd2aae8e7ad5330365213d207677855e6cd72bf93502c14b11bd2f2d6e797efc2cc5bc198730e5cc51c92751ece5c167b3328a6deed4bd73c62623bb3874c9ef18e24997e3ac93b0ad9ca7ddd4c0401ec1b942cb21dfe6abfd3aefe2588ac1684bf6b37dc09d9b9d932d5534c707ef8fe0812a403e057d00955559ca3e0f7e70d3cdfab918b8d125061fd53374c97bd0c9d19e68bacb3db46974d36cb1c96b4475acaf4d46b88a5760d2cac9432f2ce030cce4c3f853a9fd669ca36c36ff1f0432713f60e6d6bc789fdae7c7fcf4049e6166b63a12aaa3da6fc35d8783020ceb92f7f90082d4826735618905fc9fdbeb65990882ce130a7e5ebfcdc796ef293019925e80af5074bfed5f62833d9d98e324dd54e30e1d69a15e4beed5da9c6ec01a32978aa29cd26c5703a28e504e7c9264e0421718422b88ef90f6fb4e51c619f29b5fc2f600f88be036eaf28d7f5433715bd493ce55811901a59964f20ac0b06dc3a555eac123c40d3b397053501523a51e8b53a92bbd99ec3bdcd57904cfac3c0d7bcc6613b11a771d32f0f6c60c05449b42820c0a41f757ea1efebebb37f8ea567b2f7dcc4a67ebbdc00716a70f5fe255b9232e27ba05888e034fc50ac0934a43c84577183b83019008edbeb27546e8be7d8402a4c1852198c0e050296129fd66247c39abff19338300fc3cbe20a395e5805d8bc64c2d87ba27264716e211ab023765e8d454b637aa1320cb18eb4a3dbfa94027a4d75a9a2cc784cbdc22694a8f7e97bd6cea5a4e26b538be9a9dde5637be2d386a85a79ed4df541ab7d0b1370d99d2cfd1f7bf1458bedd0a53f5e6972ee424ed08acb4b49db83cae427d315d1fea4e680258e73b3fc50fdb77692c8798bcda57ac0c34823d69a8ead14c41e9613813838ef80f63138cc9ba3a6b83dfc77b6aa1248678409bd96b64c0b625e88e33262fa0bbee94fec8f3bffedaf8b12d229d0f637848a1dba01892d80f5a5596d37ac1c9c54d32dec3ca56b49aa1157583074af418d0d95a5a46fc3c234814e377963dd4c9c8a5f7cc35aacc892afb9bcede477760688e06f0b2c5a702954f4532c715151eda02f78830129b2612de8fc62fb992d1ba52da164920eb1d1dbc7d1f8f16e31c763581f4c478cf7a84cf01ca904160475a1eabae393bcb852fd550374002bad1ba0827dadcf3f6a2354a3f8f67e6da4f567fe21f55cc34840e79f6af947561c79a141721f6da4625a20fb203f96bd1a3b7322a14a0ab4a38835e1f235f772a18643824cbb9f76664b1212c785055ae17e89f590fdb1b81535e1e3e8a726a9aaf67ae2a8e67eab8f32781bc21027cb1babd932d63bafe7faf48bc57820c5e32288583db4cf369a7fbb479e1e97ca67f63b1880fb33ccf2661d7af9041ea1afc0e90ee0b4b510d094268e4576584a17fcb21b3c3f68bf1e1c4748177cb4cab92df4c254e0d0759d507e5eb096861efcf1aa66805474e3bd32f7055a7d53d47f416d24a5ac7d5fc953206db3a012234d8693e0ff662457ddaf977eaf37d043c407a7ade1fa8eaf85b6e1b1456aec3064ee858742f4e22f2d6084e3881a4783b3a9086009202eb6eb77fc1ce2236d6384cbc62c7db9cecd2fdb06f328d49c066562cf1dee863d33b48288fbb1d4d5bcafcd1b6391879e670c7189bbebafe48214d6e2b405e36192e1067eb8d0363777a174e630467673ca968ea51476b0b8a04d598f6fc593d3f3267ab37e17831dab86a67aac3ec8336c5b6e9e416b1f46d0a9e8ec6c515d86e773baa409e2afae30ea1744f2bc777af11c42f2bf6177e95245c6d601f7cb7b589ccda76a2a314dab023da8128c667a0df682f5c7bbf842a2bb51d4d842cd09d02d67444e5d8ae1f3260c4ef2da5a1c4121fdd47e953d03ff6fea10e35db2c0c110704f513b9d1c57c9da80881ced16d92faf1be60471dc4d82529ea50fd6060be18e8e6deffb15e0a0df4e36117dc22d78bd43b3fedb24cba54c2f2e3bba015bc4c817f70fc1e8b21adb04a9d8c229e9ec178fee0f35d4f169bb7dadd14f40000000062da4e21e42270a4ed0d60b4034db31ee1e13c97d8d941b2627b255d4283cf0af9044a65765ba88dcb2010fae98a6aeb0a5605d8a904d1cfa0cf8fa67a9d29670a108f014a1b21862e20d4f0f3f0cb99c97f289c657dbd08237aba2f616804ebb0e71819fa46df1a018d8336b534391596cd24b0720dd8a95e5c74b9d047da1da93d653b2aa98e67a65c3868a0c464ad24d427c3c81b41f0b2fb78f6aecd5487c29f4fd871bec21f54d22b661eeed67c866cdf057d585beace568ed52a4399dfdcc8c9a80c94f3cb92f0974b9b33ed893e8db33cf95220e03f3d28edd8b80991b0754010e7252392d1e846011defb6c46c73ee015bcb9b288f6945771af90ddd8c548eb6649efff32b0a2b36e743e46135e47fc65d1eb3f7a580104c22bbcc75ec041813cf2496a4793d17112f40333e3c874e0bcbcd889a6bb484e43632b2f9a628a461a2a5d58808b848751642b5c426c50fd82398894dc78c56ed1f0358b626cde2a0167dcb210c8ae2f6d9c95356331cf2a21ed0dfd5165bcac2681ce070f60fff5a32d246c838552cbb35a6dfdb6ea54c4ecf0ad16990901b7a72280872fc807eda1de4fdce2c223f0400e0f0eac84c1e2980b9b5a032dd1294bd2eb49372f55b9b4cf4d3c1b14050bec1344d71a8316e173bd36f5917100de4dfedfff896517a04468006e5c632c8ad15521324f3abd72545b47df874a4a95d3bb30915ebcc3ed371528f89c7e943286a8cf4ff2cca3f3496ded16b139658bd5d3323ae9007b4dab665cd24e7888735de2cce7bc1b3af39a6d92d787dd237f8d72283f7aab1d99985f3783e5cb0661cadb552293f189f75e7f3fa933c775a27415a3ad22239986364ba7a582f2d9c31e7247aa8d44d5a7e8169fec65daaf62756b34dd307ebc7fbe8a8023aac1553fbf15b48a8ee3bd0c35c7ced684f667500ab2997aa75382475eb35888e72b30ad5aad3910c5ead6797f4182adce92dafc2073f1529ff5f1a42daf3c78e499039864e8e768fb11b33c0d7779e6128579d882761f9b21fcc0696da03eeb049c90b86da8dba548058f0caddb83ec9051a04f3133341e9a17a17b72ac20cd9e242fb383365f6a2f5c795087c7ee682555adadb7305bfe2886a57f3718f30f24b52d481aa35eb2c40417df5ea9d8af1b7b871ce37fb1c84402d269e3a01a5c9a00d3c7d6ff21c90d437066850ea92773288ba925294f9368b74fd1f3c4512ae8be2f86b73641507480f3db07634df10fca86bb4431664ade710d5a8894c368660c95f7a0b8ce5ffcdae136b5c8b4ed8c3b4cd9b71079dfd6d1501df9b7f1477b516f3cceecb2def619c05061502b253af7e3deccc839de56292c95a3912e809b100897a85705cf59af66e194143d13c12b6dc1a31cd15a74fe57666931e3fd6b75512d22f063c68576b1bd6a1ab6d7f4065447daee300b7d4fe330daeda866beb44eb8ed4041d0a36bfa49871e0623eb6f5d7b967e8f969985063e2fc4f4097c2a5189b10c1776713f78193c6e0e847025936b36eaa2e817ebb45c375f18350247f6586214a200f2f17536b52b8fa196d4a6a77317807075d130a77badf745a6076b1241e47942501cba893fd0db02545e49f559e9712a60ffce9f3154459c69984de49e11192266196497c81b7c5b45997c1369c8e8490b1a748985fd4c9ab8929d17a51c331dc160c8ae8d2961351ef103e0400299e4f28faff6ac1905be2814cb02511472c7232bd104ac438d846b4a727df2ed24364e061f157c2447e7d5265b1cd75797603e220a9d2e280868f3c2c56befbc6b1b1a07be1070b293adf324b3aee5140ef5f643c952726d9b770989b07f2cdea2e1d6951027e8b386faccff07b2547dd78aa85cc113b599ab168ef602e40fc097396341a8e5b97b59032110ddf114129feaed96e85237bb4bb886b287279b96234c18947ce7d2d5e92dd5c68829edd271bfccff21b87f6a061c9b43b51252add291c8f59be1a222d00fb7719664a8b89c452e78cf1d491a036107f0a521545fd96d2548735847e278065c196153028b91f59c7b70f9883f14cfb3343bb230f4af9bd51132cc62ee5459e34e77bb2983d30e65e65ab769fa0a0578bed01f33c76f4138208659a97fbbf380f1321336c14d21012f3cc4ee2101d42321f0123d51377e319e4ff4551f7f83ca62ff9448a28b6134da582f609be7dea5d70370772ef2552f12e97cf390ee2697022168d622ae0c813d86a43c25c758162ab0aadf25c84c790fb32a459997068be01325e473871cb024ff030070434d197558b8df442e1d2ad0c7b33fe021fa6cd57b7477dd76c6a802ddf405e909d48d23321e986d791b44d32d417d63638246fcdd661e6a1453d1411ec85fa0b750354aecdd4f4b90a420d2d4f67c514f15a8fe590735f660dc5eaa7f2873c7841edaf2c0d46a92fc07c6cd22fc978f74bac72e468d96ba370fb88f9a629d4de0a8a83d43c1949aae33fe24859c1bbf8663adc6936e305cf9c56aacc84e7515caf18d0d049bec2f0a484b75a8c2c23abbca66b039a52e606f08df0a3cdd2dc6449e84ce463206d2878de0e4d0f438764a0fe360e95494e9e61581001785b081254971197024460a68ec029052f2d8841dac7e714798027696067e739cd1525df28ac9514c02e25f8ea1146e356fc5941e4661cd244dccee4a1450e4334a20cb572b842d44a8431abf4d5bb82ac6b78ce3c6d394e5969c6fe8216805f6e2db2889f27849e0dd26a5a387958a36c833a8b3d861033c00ffef267e4b09350ca1b819d5c83025e4ad69328970db92520e6ce569d5632caeb6dc42c8f6f8759256ad9c1ffe8c34a92b795bf00544714c957d5d982a4e91ec7a30dfdcacbd41ceb61f208e5442f7f7ce19ba2f0dddf50020ed1c271afe5007277e2496c3bc7f3101d6fa7f0ea2627a99de0c441a11c6afbb721037dcfc897fc5d9e0ed644b9c3aee328bc2beb3801d2bf43b1e360759c1056c74a63aa33cb6e5933b7a0b4f654113ea5830de7e8374e939e4c794be77f1f0c1e1bcedc8f584a56db0c38b6c8da60bad62b41d754d9b6cbf3379374a6126db0ef1ee2da5862acaf117408ad26c66ec8ee4f9f1844fb4cc64bc61212b303c7c622f05d29b7fd540bdc253bc948d373886e5cd4dc9bc1b551dfc514f12cc64ecc3b276ab43a4adc2142fea9c5ecf983b0841729d1771b51c2ff787ac2439f305ca3fe31cdbe24f034fcd3d41141cc0ed5cdd82e3171be1381ad4f0bf81b3be200524c98cad5a3dee3ee618c97d0678c7b4fcf729dbc2baaa2385fb63e6b906b08681c19d55200924c0edb4c3b48463fd9c2ac86510ce1e0a641def11e9e7b7fa74a629895221b06a15c995cafe55dee6c06e01b34f4f18e5ffeb76ffb412277bdfa4cee10823a1e55832c3d1d19ba5b84560668b33fafc672cfba1a85c60c61c45bd562506d9d28542c4b4795ed011a8005862f7add9dc2533dd29d0ddd534eb0a3b537b391c423b527b3ae4ce0c829a6efcf8671e9e5224df6ed6c1f20452cb46cd578a620788f9af325d45825ced3043ef3693ffebf7b881518ba2c71587251edf150772ae1e24f4415f9d9307151b8fbcb83d0da908f4b6c762b777dc406991353e962f181bc06e892ff9e000000009dafd09b291f79720b866e46bcf14d5bd1ed15a468a8996ecec8ce3d9890fb45c96804dddfe5b7280c0e30934f129e14b344506f70d484eea40baac63b89dc71b030a6c8149ffca2434c773bffe76bbf2e778f0034666970a96bf336ee5240e765ea3715382bd8fe19c5ce5a8814717d87d4d6304a3b0d6581a6fed44975ef8a8186c19a513f5c6c0610acbd31fd58e2cb683162464cf7f50ade879461ee91f433b09d1febe058c101a0ff96cbffd547c2beab15ca343cfe592ea435f980ff03e0aeadcc80d64383d287997a6a937fc22221cec2a1aa6e8dfc1dc6e0f2e02060a18c09957376a72e165728acddf73873a958f43bcd2e9c6c71a83f744bf14c75f5e8308523a7d39bcbfd832c6597b2928b07630ae50540bb71b44b5b4040a1d172fabe8dbfb96a99e7498b12dcc8ed9e43fb36c202d019b4fbe11f715f5de76bede175c22d8355323eb004c5021d892fbe48fa7b6bf382eb03d0e447a38c63bb7fa1154c2cdf08a1cf5fa95ec75a5aa9037ebf8916cb78e6da650016a0c7ed34290e25e2122be24e4373c49c4fc81c39ec1a1ce4b658e1b80562bf911a1f6a5fc2e69d2554d4abf5ad79d9c9b7d9ac8c4122c11f590a35dcf3e7cf975027832b4e2a71ebc591a60bb874b36b415b455bd942fe1a69a92b70ce1a1c867c85138449529cab5f63feab609a2ba3344191c416d8409b59962bcee1c4a40874069e28432fcade20f07c9259dec75fb978a6b84b6e8f50fdb341c7c19f55a8fa389cf085f44661c9618d56d32be0bdb3b2928fc2c372e86ea109afaee022bb832e80e869c7cb1053921b862b27599d3665f7fabfd6436743ea893ec43e4e4daa598127df8ee3249be4668d717117a038f0e734a894457df4c64dd76a9d9d42efc29f2311085c9e6fcef385f40af94f283edca078797e96b79719875aed3900252c3acc6a92e23083b3fa24057d9ebf7886df99d652e7068cbd445560a0afc81bf7c011777837f94b32094fa1bc99472cc2a40bff245abb27d3f628b1b649fd00", 0x2000, &(0x7f0000000a80)={&(0x7f0000000180)={0x50}, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0})
syz_fuse_handle_req(r0, &(0x7f000000c0c0)="970b180393e57da0084004606e0f7eb55b4379b678ec58dd5832867fc4741e325499108ee901f5ade42a10a2a5ca59b706328aca067422dcda816a63687f6b445fdf7c8c4c158921aab593be18f8f3e3a72a3c634c089c468f2afa55a47fcb36c8ec931a3b8e995ca8f9da378136eee8d00878a33e262e3718e8829586fb5a3bdd2143ea5a880a6322892369f494dd40593794a88b4f0e69dfc3d573117dc27d511cb0b7e7d1c13dac381d4472cb9eba0637c9611565d496c7a6936582144f524085bf34af3a90ac0a0db2f79a423fa8b797909b65b72ee23068ebf92a9ae53fdeca4a47ec6838e363039c63988cf6f4f393f907cff08e13520751cfa3bfeb452f120d8a5f462b040f8537f7add203eb2b2f5784376b4e0d85c027c4e0d5817ce1db986581a147a5c7e820212907992afff07f13a43b2a2c23e6f61d7bdafdea1d396e0fa1e79afd07195dfdab53cbe75d4b96971caef941b69525b87d59fcb99bfb348a12236968f9dacbfbdc4d9b0b01df755ba3b6c320a29e5bc23bd6b20f3b27dc3d63d2d2ef11865347c5ca1504ded5d549e17e1194d717c79bc330ebfc3929d079152f51f3ab9701a3241c7df4130027ca1a6d0e6b5f2f2c3b659cbea4cef19728b45f1325e04151af66111cabddafa17b90f193c52d1c4fb646f99fd42d77a3f16c05a491a775962a2a4ee9f9f6c1a5eaa68305a88add9d6f35815f37cadae92293a0db1613662f145991ba5fd632c4a170588f8265e11b3e1a4ff2b17f3664b98d9c6f54a356f19a9b72175e7eb46ff4330812993886cd7b42ffdc3767a4ac16dd21d76417b70cfe97ad6ad0ddea7284d0e3ecf0c6c6b57833f65963f3764e297c994e0181bbf693c8fc0e57fc15b2ad776a00c19a805a906ffa80efa4116d5f5c9863a74bb340008d958db841c5f1e3b286afac717ceabcc7310e75e45b61215f6ba0bb496bd5e094b6139326758c1d81b176e11da5eda522f05346e1a71a6358b4c9b7653a66ae7153858fac4695d64fe2962b0d62d6d8aac14cf9cd2199fb039b54b64f5085434b2339f90bc11f2e407a6e84557de9a7a7edcc3b15a7798cbc68c1b1e1a822103bd43b656e933bfe886736a2bda6ccb228a8e4fae5956673db0105999017d8b68159f7a9480fd2ca70bb7e9fbc8f4f1c3581b1f528c8fb5b5d6beb769dd5e9650739f3cfcb61ab7b066c342a6c6886b0bd83f399e3eb74d2cafce7fc76febe624a37e185924afa8695caa7d3c1a97fd6684979ef33957a334fbf10c7a9bba18397082580df2425129a87c4868d41d1bcda8a7faaf1afd492cb4c83b7c5ce7a950f92186cc07bf27dcf58ac56506f2453399070ae8e5b009e40eb1970bbe8a1c9f3befb54255602bd191bd46c56c0fda2842462c0b68884f9a922d2a8b161aa9ca2c0c52bcfa26b7b7a152f2ccd16ec4974361f7322dc3b345e926e1a1b56200dc425e2e03c3d7194f9cbd321e10de387adf9790a5706bcf05d9b8c16e40e5633c44553c2aa8611f7656fc732b5dfce1eaf212d2521eb013fcf154d251553ba7a6a1f7ba8b7ceb3a1df621376543a451fe76671beaab4833f1be28247919c7cdf4177e2c9cca78ce52b5a7e4dde913dd8b13ce861bbf7048822041f4b29b3441b4880a8f7a4a289ad3c6258494e7736e48373408d248c3b033372ebdb3d9a406869445b5d956434a576b83d4a7e7b47ae8c69f50be20ea56f171e592e114602ed4f47e86dc34008770940adb4f0167811c474ada06693b55f567cc3201f97c08a3711dca486a86c367f59ce44259c1d71cdb135aa8630c4cae61ad07998a2f781ff87c946e8aef9bde6d4738bc009fc43fd176bc38756a0ca48c382395b48bc55da32892551ecdd0bd3f4c69a79bbe600f4103f21e443821492b92516833b231942e91a39e7401a42ba3e99a3a2fefa6167365b9050305b6f09a013f41e764a80f422cce051e5b30ba6528540ee5d4ea5872572c85f321b68e730f40f64b648be31a9e530718ec17443a1a4dcdb79cf799cfa75d0bfa0fde71828d8f51e38dc3d1d77430ceed007426f689d5843c34afdec5dde3e480a36ffa25db4b3483cde91e56eee8756dd953a3abff11bd7901d6b37c8371b023d7457361908576f92990f19e9f48dc58ca550e61a035161f1539b14b7bcce535b3a3783021094129f312c03e51df62579ae9423927021e8bcf530116f3658a1e94d39a800452f7461d2f001f86b911a8a14b9e61c2fd8f959ea40793df240aed5e5862ea59d78fb235788c1ba3c0ec44fbefc29c2e6f22d70849750625c3c15227579d42858b5fac30bbe86491697cec1c4543addc1f50202fdf77a6d2d23e70ed611a63368694e459012ebdbe71c4f702980d7ae63aaee33d5f8df5fce071c73cd918991c6ba2f95f33a9917a22c9e7342dd492c9e2c2f6457c3a48f35edc1720f2224f2af2ef4c0a38b75ce27aae5d5ef615920ab9245851590cdcdcfaa7e5a66b73f5a0a1bcf1bab66ecdfc0dcbd8cebb1b98f6256cea6761c835a761819018fd9c3d2f541eba25abde06f1551328800b1efc04d8e10594dbe95f9f10005cae8c5b27cc18268ebaa4578f9dcfa99aa61567a55b43545ec729764af99d224cfea6a36a93d4f70bae3225256e179e81a0c64dffce9c2141994253af664c33f881aa417fa3b7e9424f1841f1aa845ea0fe05c4e47b318bef60709d6f20c9eee6e8c0c18bd161d3dbe57d82903937e10c41aa9066dcee124354584232afdcb60d185bc39fcc5e7e5124d17e2f998b64836b587cf233469b92af65a70f4a8f35df9e24c7d5d21bda27ae44ce6706f86d3747db675aa329e8b43652bb1e89687dd003dd7924d300f498d444639b3fd413840cfa958e436e5959e95486161af807cbb7304d99284818eabe39493c66664e92143ff41602a3805369f461abeae5e5b6987a20fa47495cbeeeb322c848147dd9a052384a49898138557e10eb015df370d01977083ad24c7defc8c80583d5f5eca20d0853afb9f41c356f8da0e2435d423528f67f091fc614645980a57ed893ded1c3d37881b243b8a5503f45672492f3849895c9377277a91e7090241832629032872294896107628ffd1151c444153f54b484fa3e5ca057cbe073e6039c11b1eceaf7e20eef2576aa99e7a3f36aed9beb089af28d82e2dc5e97da4878b76b5224e1d293f5223c09f715fba13945695a98624eade1381e31c5651069805e6f707811586f5f81e431e8624a608ba1ab405d2593b1f9f667b89d82e60048e4ef3be98bd3078beb4e5e66e8823c8b427d6f84468f1f18f1ff8a8c11515426993334bcbe0c3ba37b91be07eb800fb2e00a24351457d8fc067b4bfec43c0ce8cd26b23bfbb27d3da7bca3efb7fe6f7715760eda4e3a27a7be7419b803667ef6057bdd5d44250b47fa156af04db91fc57f25425b3cfbaf90a840fe5cfcefcd1500cf4908ec4df10c8bc14ec284bb99b13a8f6136e5e1c669806cb5a4a5227f7952c5b605a2b443866fae399a1f8fea323784935c3e5a9ba9e831749efc9b8228421bdb91afed16341962535cebf6fb02679e5412f67db405c90e218789b634d92a41aaf528c92b8bf38b629a1797c036465b77dc3bb124bdddd309136681d3fbe0251698da27c6f89589171e4492209f7eb48d50a161a5135602fca3355f8934f879c54afb91224901b635ed372fdacc9469471225d2ef3c980466027b86cfe3d664071edaa29b47455064a074da56f4e098ddf27984dac546826aed38e464d5c5a79a3ece544cdb3801de0e29bf5164dbcc14578e3e6c44a4a9041e2315f1243358c5949377352911e0a67c6de7e11b0881af528fe478c34909a1178a8a4f7fb727317e4f3981706d9c9215224604c2d6a4faeefc21bd635c8412931ac4feb2c60666672fb6dc5deda0d6c4ce31f2b6cb45907427691488abb280c3fd001f3d7507c0db358af7151d3b8e2e98eb8a78ee69966f7a1307882c5b57530e0dab5c57f84852c42db013e3448da2fb0a754ed97c001f33cca549eb71d7aef88d1ae7fac0d96f334556d75f600a029ed698ce9e4302279999726a57337b9afda0b0292c14d1687a85326120d9fcd84cdc02718f26c12ca28cac81af0dede79685233be41c7269c57100c603a4f9536f757fa753353bd0cded7d4edab29dff6f7dd5faa81078c263c9d1d7e662a0ffae22d8d12e679de9ec6c634ba46ddf6aa86ac0be41cabd9b14fd12107ffce96915fa0154f5b6017fa866d14ff47754a58ba14c1a3eb3f23f040779a788b774604c3a8a7dd818619352cf47849eebfdd3b49b56f376044e7cb218759059fa85057f96c159ccd63ea6cd0bf47781c2d023411854dd3ea46f4913cda9672655e566d2e83fe2e0eb5476bd6fd7a84557e37a4e8d32c75ab51dbffc59f0cebc3edeb395f38f82765ed3cfdce75b2fd570e783c8c3afb31049383af0b51575e5c9dd9332bde6f684a3e11d199f43004439ed535a20c7f2a695cf9b547985421ac62c2289c71491f0617d23cb7a9466c8f0482eb2e8aa782118702761e0267ef500afc52f4a3a7a53ef22aea542f679dc5c751c766e06af453576689c87b3b89c091e5444ff6fb1472fbd271fffb268a2eada125d7acfc70c8ff4cfd3f5421941c2857e54ed0617d6430b806d605c2e508cd5a7764d6ecdc69dbd050a97f8696535585bbb95b66f751566ce612aebce9a0b021f9fbf067870fe447dd05e8c521413e7f27955db3b8239836b6ad120f5fb48e9003bd19b05f94752743d89bdc5492c2ca1bc3133fe0ceb29451900e2ac713cf2cbc3a531048a473a195ad40c685b539f806f434c9e2cb6a8a25df84d41c13d1ceb90de1a3efecd06a53ac9a32654d1ece86dcf6fa17ea6a4f367f9b360b3e26514bf94af1f52d9c0b0691241e3c6c302e7054bb738cb234019c0e45a7db270ab9d75df73568f25579d33e7b42743c924b1f888df85c6166228f5391962b689f0a4d9683b43ddc98982a820b5c60d9c4e3997cd2212fc3850b2bd41342ccbefc1e4ec2ad7ae285f156f4a4f383281018c73ca4f2e9d255487a9717dd39cd744a000c68c53f82a22a08bcb734b5bbb8364180991140c2e727dfce4b19e70c968c97393b56019ef84688772d488b9bd6fa9354ab64f731e6adab543851e5ca1470fd13d0334ba025b57db5d9ea13c970642726284fefddab8fdf7155f5b8e3b3b86d098c4207b428bffcc7ff76f6397b6a3efc3c0b0fb2a4343b4051271f87e384c2b659086ba668c66a15d68b87faf82a60b184f27256e36a9ada7c4422754be56dbbab50ed781f36e40ded65a30378003de5b5cd5f80a6042613c76e80851312c7ed2c07b762b85a1b6928a7b2428d2bc7a6bfdfa2ba55aed54fd3c878ec655caf1223245433b7c6fc2a2d3b0393d7ba4e12f26a53b9d5afdbab230b9148f061df2e1c0fe73c2abcd142125367fa5e598e500263d9b27e759c08b7debee4695a5b192d968108c134241f236cae0434ed71e5099cd466cfb04d5f7cef2e94683172f82a9841610cb6fe55d4bfe73920992bb76f362b9cf7919c906495d4b37a915d23168fd7ffc2f36de55a1b17fa2232df03663ffa2a4c5e76aad90fd5abc80b6dfc16ec6aa328cc7714dc2d7bb14aae9f86c999e93a59fd18fb2300539bca25e69b04943a16c985ff481a42c9d8af43eb61ef7432b8e3aa5bc391c181b7d546b94ac659bc4b501157d3adf9d4cda4e298a4e4271fa2cd08919b055eb3f168df76c1f0b0d5cf5760b56774f105e51c93cc03ce97b00768b9620a6fd5162b9d9191ac0928d2460e4e821a276680cedb3b8167bc156b48a34d4c24d4a87fd09968a725d4b6a1b54b169f1e14143e97a84cf3d8eb4ec5458dcd5ff93365396c00533c3493847f595725a4f15300183eac306d16ea136b97a9864d16330d8c5b8321a6947caeb9cdc7ff4e53c419518ce9bc11f7355651be27a2c2b9ff4127ad86b96c1b5967def371d5d6a3f365abaca55c5f19600d1d5051d320b065c2f78f2147c170b9153a0eefd7b3f1e637cac3fff14b0eeaf472e6a6a9f7553ed3267c911d4d77a4f7285b77df725b3a88fbfd221343f656d60b61808b52a8facc81b8516698f2ac50cd8769371e67278c59ab1cc890fab36206b939f23b31ab976651ca8a4e7754bb10d03d4cc6506f13d98f2bda76477a69a8794a34614a88a7ec94e1a229ad6f747724a3bfb674cc87ea0dfb610f66057671f664206672e78c00a3f4585f17fc40827d0c8af88d3437f811274f662e9ee73d550833d0c8fde449089f8b5e8a25d25096537ac960699a07ebb51271a8f8556037436307063282febae745d53f8db65f13f24cc2e525ae465c9bf79f76b82dceada3bf34529321f913dd18548ab2a26f2a065028f46f4dfb18294dff30a7e5b131a08c671787baea45545d15629ec2f435d9138e517055cd48af7120b3b79f2275baed8a4b6a0f33c30890105ae2c07a332df79f2fd6767ecc66f1ed628c968a2685813342677a2823d10263958eee79d03e393a557475701694b5ec3dec8773f37b980f5812f1cbaed6e5253da037b5f88ba2070f445d74907679460dd48e16442d345abbd37f7853ec7123ff16db46c8571987db63ed711d36c05c2dafac47ea366f9467624b6296a2b9fb7056702d4ba38b4df72e7db3244421f31aa0911af3e3a09f9e08e96aa1545c37465f990bab4ee2821b1a701aa707db1dc18d52fcede15245f54a5f1a47b0d82c33fa378625d247b08753ac5fa5444b2e3f9d1d3918b154665b02fba87e39d0e27bdf60b27930eee02c31d847d40166544ab9ef801bd79bcc8d93980354021b8c7a1b9592934a90917db115bcd92068a970680011cb074da705f1cd06a0142862a777c6a47afd38721979323e27151c114e8901d41f79358e78289af10134e22d903415e2ebd2edf34ae10eefeec219db7b13ac983583dd4b02dcc615c6f70e6cf35ea216807c4b9c81482c2b941c7d6cd6621d9480ba924a3372ca3e3ca78438b0e9bf7c8436fcc0047b3bdb8d70190076d9feea778005d5d69f1b1194c76dce628e17b6beb299146b25f3f6660263c23dbcd08f70ccb45569a81a140eff66f2190110cf0977d9df7a2c437042961606ca1a378c8f59a310ad6c9cb4ff30a2d55411eeb38d927bb4d0f60ae75d90ab78dad14097f6dd38f512af2f932e1ad6a5e201180373689981f23bd9f59e4ca29244a8ea4236527fe2249eaa299af174f25b13d72b181c2f421652ece630ee1358098c29f84506654ffad3647792852a7faf107e36ae330886ffcef6e3a1725495e430568a9cd85d385e5a15d2f77ed274be3c8edfc52c230d21785b927bb8e470f989e8c89b01af8d04fc7050fc978013fbc5dcedd2baf5e8bfa8e2e1d3f193c224375db2f71d4655d2f647e9b1739657a0ad8ef6751a88151a3413ab870e0d7ba3f0a55ce3f30d55e8eb9e47e3d82563d9180399e7895490b8561a374acf5c94a1c648fa06780c4141c58ed913fb92865d3b4883301ba69b3f2b20c1f82024bd75e62ce2972d3219bdb961ab3bbac8f1d873ddece6d85f540f82c9d79b0937973335fe05e5c6ad8fcc525620a57678d58c7c2f0f157e030736d0fe4f6de520b390794cefdc6c828b4512fb6b2000d08e38693fa22834e69180d31b3978f9da75389f919a0d49ff961997d14ae6bdffcfb179c2ead52c69dae97416eef2602843dcbe4e5ae613d429feef7ffba6a31a8be8bf2e62c6d374c807363a986519a8cf9dfc99fc6607486e10599ae415b51e23f639194885e5119036e0e535accb4f126b4c45c47a53658af1e049daa2967b01d9450625d92f8f8e9d151633646044fcc5f6ad835479d48702839456decf070c7e6143cd31033810bd7da01c4a2cfb08605b25c00336f17d3b5a3db48866ef864b8d9cea9530429d3fb1afc7ae9e7d06aea9034db89b2ec8fc2a96d8d701fc51994305077dbea527bc0fc398b6bb7d42f0c408be69b98eb173d285fd8010ba75c57f2dd982582153814ff959fccc78aa5f7901357f6129f840af6649534f9ebc7750a20502a7cbf2d2f28c6f97884f43779bbbf93c550f8e79949db0e066538456b4e966761656eb7bebd5afe9b9fc241711b874682b226e9c6baecc1e909858e01b32472f6f8d483c073d3b576a4b03534dc4b620e21e6feb4bb2ddb37e3f0d4ff92c0af19e6087034c72c5928707748bc10ea22788bd938a0e6512cae4733fc1a2e47f3d4961932fe564684872922b44db143bea77580b0704675290e0839cb5ee529ada8b4c0bb14f05c5c396e29376f1ea80dea2852a88ddf8929fd402571fb242ead60d2be61f1662e1a833969e18e23e0b808900e7ed4be9d6944942da7d384739da1055cddc94937e1ea4cd305bf161c407b471df0ce3fb3413c5bd511d3c65e70edeb5397b0a8701538be7d2f1765688cbb0379744281231e60f5edcbfa6abd177405c455f77e30b95011ae4fda2a3c6d3f9a29bfe7656f6afba48358d57b4e1a84ebca241b7a427c6f806d1f771b540912f05a6df0d5223f85639fd7c163799e28abd08e4013aa43ddbc11ccc9d53131ec5c75f7682481968ad13ef34ba23d4759b51c4cac5a7ca2c73b3103c5b9e4b8686b872edcaca791d669589655e239920fc088eeced3a131ddff2eee9fab3cced40163eebfb29a85b3e97bbd97d17c3b06d3123409f115cf3e3d1c74dcc359664ab942e6ab36c41b1af4015ff5baf700eb99abd658e6833039051a235a2f84b70cb8d90271a481ce40e2a18bef8dcf7f54952b090bbaaaad391cb6cfa218a1e823ca7b16311e35e0350dd8016f67ed34771d7f3a607c1c9ed63524ea0c865148b05f1d017e475641b5076df632b7c261ef54c23eaf7cf52c22864a8ae8f8c3442d147fd52a801f87665b47e229a77b8e85c21d7996c7de9ac4899b098380f74eff119369c81b21b0b916017d0b604ca2a74b1424a4c3132d265d12a01ec2e8cff9809ed2f7891c55bc5cb932c6ea3cdba14cef47a2a0521e36869e9d62914447c3e6cf3da9ecaed915dec41e81605a46a4ec71a8b5ec0bc2f62b3237de7203e4b6d01bc32a5b2dc416623936a324b73e0c63ec414ce1bb4b344db85f014979ae866c4a2c2cce0f814862c0691883dd2d7bcd63fdf2ddf0cb2c6a1a10aa878ba997b74db8e894e4a7ed5e8ea1e3c0b602bae23c6c8c5f38b919aeef5625501fe5d4759c43e90de56122f3ecf87e8023f25e0d3ce64ab629409e881d2d1c5f083da90d45907e62ce3177f7982e514779a13f70bc207d9aa55835e37a5f4782242681ff46600ac9e63f90a245957440987b54b3678ae808c481d25755dba747cd7c3cc0fafb9a142e1ec1a9a5f81b5cdd6dbbc3a4ba5d49f58be6196c305e2af35fdbfbbae02cc4efe771d65e6000ec3f6cf394650f5144308c95279b9df3b29236a32ad3e9cd377296a4252e7dda1bb95d99c32cb81d970de4ff47760ee087dd2fa98392c8ede48391b49cd40e314adb896f0f5b08ffcdffdd70775160144552b13edfac23a09d53a4a4a827a1f216b2827cb9fb47a9fe6412d509d35b754d3700cc0dc8d7a3406a53bd1b0ee5112c50fb8f805be52a6c4e1e664d174727f33720bb371fbe9adc747a234013fcaadbce5cd2d416414b1900074e3ec73a36f32f9d7baa96ed4ea37aea560df4d9c724c69b440139a6dc1758bc74b59c521bc59958da71c4e5c23e4a8999305d989369a9bcd10f0faa789f4040950c349ef0ee910a822ba8df4a6cc16bd72dfb85d7c9a97911e96541a7fb6fb4711cdfe1e1083b2e8e870e2d2a7304f99296a496fe30553971b75f78ace054a8e3c6d54d40b2dbb2ee38a6244139fcba31b88a3ce91d637e7c88db35794002ca28533a46af85929f603e4cf4f5aea715ac4495d2c07e8bf79da078521fac5059dfe6dff61405fb6962987d15a2c7b27a851e3076803c7b4374a85f05b96e9bae91656a003e9acad767c9ac88b339fd868136b63fcb0520a2ee2f25128c8b97a0d43d60be7436756614108cfee63fb0fd65cce0bb0afcf5ea7fa817134c876c949945642a29d71aab10d05522b4b1788bb051ae1ad23fc7e75607580f9bfb7ed901a66d69e79ba742ba169f7e0d36d0c8482d3a85d66a9fc08b3e4c1669ffb4f74f418d4317fbf03b785859601b9e3af056b6a2543289738fe1e601e635ff04d750f8724bdebbbc920a7ca2f99cdaff265299bef09a2e20878682f2f37e46b5d2d3ade8d857ec6d3f7a2779080a5927749086b33b22def28633d53dae49362b4c4d47d2899562a52f22618a45998233048f0e54ba01dd53953c9f508abcb0acb1c1fb1d110e5d6c14d707713cea4cf0403b7573ab5b0a1439e6b2d29c46a3077e0dd296ca751db66f829a42c5afe0304c48fbef52c526c8f2100f6826fd4a5295f7492855f841fdb1f8487fba63b6db19af983a75468ad29a2b6cc58f9ef2dfeec8d798d60e1950731e65c5e2ec1065a22915a30845a5f87a26c067ea870d4e1ef71f67617906080b7b122b8ac9e4da1b05442b5477ee97343cb20f2587744abfa5f318ce29cbd24df1a6dbd42470789e17ae8115a588788d910a171b88dd1b94228728bfef3b28b2b32f523d603fa28d00cf23b0a201658f28ef7920f36a0da8917068a4435e0d710d320258114e2fcde2e1dec0c9faac26d671ea3735ee2b26cb644ba56ced9031cdd2b391c4b96aee7a4c38063e61dbd8ada24cea7ced0728a365bc2320eda9746823b7d83afdc8b3b293b56739011554000aec6272004a002328f20368c0902b8a8d251afebfb4d7b427cfa8927385626a474e3918ff557c8f19a8691011523a63c7e578b98c8951157f0763db3ebc4ea24388527e83b149ef89d4173ebb1c0c9aa3cf4e1a47faa3ebe7ca625e7ef077b38235781236797360696e552b9289a80491d4c3e70ff00b01540deb0de1b3385549b667cfa3598a34751868a14ccb22a420781452699563b16d0d0f1a7f0ba3f0ff45cc2d2536f1de9e024bbc923cede7725f84bf3e6a645f43c4ab3db6ddff671f283857262570b6652dbd8c869ca6a3896b870235047db08a54e5c39d7516c4b0d621d87a9c3e8c53249ff2ab9145f026ba4743a46197af56a0df022363ed59a5c2011e664a05fb952d5ad9ee2037c59a4075e4b504d91e87d303e0bc55cccaeb17e1cbab6176d2d148ce05fe986c79eb843886194f80e202c4f373244b38fd46643c1bc0fa8723ac498c71919e4ed8e5092832aec00a35ceeca94df7bd2c0c02dabc886cedf1fd044db2b45c30f8c0334c992eed40290baaeeb4d00e2cb504ca1173b6b6eec8d2aa3a1bf46e64c1ae1b3ca2882545729fe78d5e1e99c6f1f31c0b0f2190889c7318ce7605128a86c62c8a1fa107304c4609e28a2a43c6799ff6a7d70909ee10676801ee670004cf9632e34cb8cfb43d2f477ad335f5142da0baa4f4542dc93704e93a3420ec50284626fe36618b079d0db013d691583aba257947bdb1514d0318180ae43d0f94712f5c0de35f3e342ce7da65f755761506b9bfd186641fdbd03d5a2d4fe170fe23af8", 0x2000, &(0x7f0000001e40)={0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, &(0x7f0000000e80)={0x20}, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0})
syz_fuse_handle_req(r0, &(0x7f000000e0c0)="f1187c2666e938b0d719606210914a175384a7d8bfa08a4ce1a6704c4c59dca5bd31c2e0daaec1bf1788b64cc764755c8227d255c9fcb56cddc8d23a8719578a528df745f0862275073dd2c88521736ffbb58e980e9803aa1406002487d226afb38483a478d98869748c28d604cd82f416f3c4f2071aac0274092945c94a4911345f1fb12c47fd864cef4bc44ad5fb5348fea8246b3604a4c9c9a827e4aae4f7677d023169ef281c43f5341372d459170f25365fa911efb58b1a0c883d98677cce26aed7f8410a54aee36c963dd8f82fe532fd73594ee6f83265b5fbf2507319d73f87cb6d2050a7b1e001ec563d4170d9ca49e019c1f34a3f6a29e4adc72fcc343bb15caaa44814a11a621d682070b253354508d7b97b1439ad827954b305797e4de400c046ff93c99fa15125daa8b53581ae5392373621d5beffde817abdd5f4feb80aef8cbec83ad2a830c773ae907c19f5385e77e3adc425fc5d8dfd53312af6cb6556f8e3d871add2dc48a37fc05c65f32149a0ac179386d1016590ed19baede89d890902306e3ca40ddf9ea5f54b51cab0b6bc1bdddea7e6a64746cef6ecebedc1c51c670b0af450099c4052caf1eb0d4137a74f41f101a604fe08ef524e12f8f831c30e15da0947f6f584ae2ad96de45e3143f5a9dbce67edbdf5904a0ca1db282fb70dbec4870f6aeba8a74b24900d7c5a0758afadc26ac6f93695eeec1611d7a1123098420302ac2ecfb31bd545695b61c9f36663cf7ce86cd7ac350670893acf0d065fab2dc2ea43505b261393d285fbceaebe30e0d1fbf8baacb9eaf9f6ca84c598c5604fd4b11412a027760671956d312a4cd2e2dd54100519a0a8f93f5b229728bac624870cefd815a6b6d1ce8b06e045c47ee2f91e3524493df21f46cdd00a60c39f49d29965dbed6f408c42b29a3f76e0f840762b273628f7834397bb37d931231ab16f6cc7bbb5caac7a83fc5ac8c67b120b19d8dbc3ef054e7490851bbf11c4cd19d8aad281fc054613050013dec6821e034f10413f96e289f81f10a52fc941992692b2c3b849d949b5c6465f335cd7876caff414d0a00ec927c2766c83249ca5e2d5dc9a524ea5142375bae891c8bcb34e8b4044964b8141841c619c6b1da249cf65b9c16506926804e4e388b60638c46128b43ab76a32659a5e3fa64c75609e31cc2738392a868434d9108c7710d72f8a34827943ded46328621b39b646cb663500467580b76cd6ee0217149dac6168499edcbff45193f49bd28fd105740f641f341ff8ded97ebea072d805062b35819f28541423b0e16ef996323f5907b0b2a0703e9fd5c6a511787cf6321a87f648170efd691aede0c178e0daf53da03829e4e7617b5b834c6b4196d926c7d7a54b9f1b3d3bc09bb7f22fb18f09150e34bec2102eafe634e13454a9d5cdc10da8e880cddaf892af35c437768b62c73f67ccd8764c34669a91f9d669fa1ebcc4159e4be7d4e589a59cb70c1ba77ef7a6a2c6fa4481c5f2c025ee26e24ea59215f971b1bd22af51af1334432d149a9574cac0d4cb145de1038fc37317b947fffb232209f8c65dce28179c950c7b23bd1052db323662512c5fb41acc84c4e42d1daa9be21e6c1d22b6bedd5f28d2241afc578e2a33e12d1b1b6427c620ce5d80c4a5ef351b2cdaa598c478b56bf79d9dcb8b8556503c66b44b27e8df8e046469a5da9390f58144b8766f9f51d39e8d5bd44e1ad024fed57ec1a3b18f04e6bb3b011f1b23031d85c498766cb10f66e3868a76ef1e388018292fdc4435e14bcf7ff6067535ee3764d8deb725cc0fe0afffe4285958ec9595ae5c5cb04834d15429435272e5b0510f246ce806895b85ba2f81912f76f6b955e28febafbd0c2e854479c4a6150b85c05bd54a1d0d37877e6fd3ae20046380dbf82bf9c8fa8a8d48f76cfc376fc9e0e4fdf0ccb785e9833c6c9ba006f7e59318ac733c3a1250f40ceb7ac3a167727bf89daea038372e212f02cf677a009cdfd224b41fc3c142b0882a53c1b9b7de6e99974d80ff8506c71ad3e063d7bc5c5366042b1cf952c6f76fad74fb16b9d9c9804589ae4f4afbc7bbaa340c1093d76a01fb254c5ea168e83b39bd3c97b8ace4f32612b63e841fd6eb304a663e4f43fcfb5f435716df89146d0ebc0c1517734ca4c90b9dd5db6820a4d730a9a7e6748d0d2b7def30a1c242fa36f52c3f685555b0828e1dd59023290ef4626d3759462cad9371d72a9c63824c91d5cc304ab43279f199811a604c164493793886b643ba6bf53d0a9ec7e304488b18bb2eedde5c128b2ef0303f85ed54875e38d4adbbfd477e8fe9a2217f084000813aecedcccb1dbe482b4856b9ceecb28d40bde5e8376eb8c29dc71b85d4b345fc411937234b318238e962f0d5dd46fdf5149685cb3c4f9c2710f4173f4ec616f7036ccf83ba228e1cc7b205cde9b57f00502d4d1c2af6dffaa37ad30fe0f5d955cfee2e00f48cb7ba02ab86748d0238914c66ca9ad9ff0e8b397c5e527c56b0d63a9b5a7b1da19424bc0c81d627b1389a42626654d901eff0f37d64e0cc894ab2c4399c67b846839a1c40033f4f9ecf8410fc63672ad471253fadd976df6510137d903a76ccf14509dd8839024608d707c4eb69cbcd5ba9cdddb7fbac1c963a99ef6e75eea8924aad62d6aea792042cb372131a83730a6ee7de386410d91697dad01d85ffcb22b3679573fea63a38c192b1b1e3a722adacaaf8e855843e1366763456c86ba9934302e0abfea2044386f31c457cb7ff445d7b00e3ed7d1dd4b2f92c845f65af3a3f68de96dd9b7bba62b7fefb52639b6796ca56d902f9dad52f42a1b79fc814c8a58033daa9f43ee3c540cfd08b0ed21941d67dc3ee37fcb855fa4a03453833714d8f8abf83256c503713adf7f8aee122cdb01d0ed27945d42633b0fc3b2fd51f8a9d403e792c9b77be56c257110669b46bd0f8bea9ec7b895b0b1bc9a9485a51e72763c3ccaf6210af7652ccd437722b359d20bc124e7055c5e41ddc5eb66f966647a3b91f1c51f3c6e340d6e203fcd30f39dd0398f0a1c9fa58f2da697033f5988cbc6e5c8e1fce7904112964b2ac5f938b9132d680f3cb0d8ec2fb65162113462ec459356bc9d28d9efdeb9983d79ed04da1a78f02ea8f5b42210a23d9c98a734dab4069dad2a532ebced93f5dad2ec9290b0016e6db7c3c9ca3ebc71d805aafc113ac93d1e68c637000879fd736cd8a42474e607da884df065a06f4d64054512a396d99cb7dfaad6a91cfce8288cf995e83a1ffd2ec83483a807c7ab3d0703e956222dbbc2fc5d57661fd186626b41a2e18144d592174cc8e45f1580593206e6d7c7f3236eeb41aa772e663834768dc21a4c216490612e6e912ad48f1d90650f1a9a29239ffa8f00747833038b75e8759c50799eba59ba58a1ddd3d9b49806e2c7ae143e88f704d0a5556429445a41ad83a95e43bf32fe2f6954ca030a3f2697014cb351c89cbd3d2792cc73371cae124e5c0055201036c7c0c73d94215214b33234f4e21071743cd553b8d96e3387151860f5143f16980020954d80b7f60955f9c09a6501e9d0eee4d8793e9ca2d04a8aa6831d2e54c0397c6c9f2486b79d06aee46f064c02e77fc4bd7bdf31b9dcf520e26ebb7a02ff3d9eef1357dbcc83877f5613c7a8c4e3a4636d2e0161a663a946f651cb5915f07762d00c62d2ecb354d09c2088c3de6b59b5ed0002a1fd5f7eb316ab62fef44af65abb81f96f495f867e128e8829a3d2693e00a5b2a14a6b76dff7c1cd80e26dca00482b3055741fcc7973e33346264f268e22ee4a74fb45066eb24cdbf71ea7c69d3fe9e9ce52dcc7e9b0645474ba2a635c36a83135cd98f892c2619a5724faff0aed7e236cad81184dd05dc5645c7e7ad52ef76d615255b2936bc40f0ea017035a8bfacc18c7bc52ec0e29d70126a6e912c6d06856a12ec2792738a9a1c2b2bd1e9b39db4fd115bc901e0d3fba472ea0182604cc9e73cc772117d49dbf41c7098076eb0867d8eeb7b927701bd5cd21bc2b32e4ee2ab86f143770b4718f7c9ebdd32fdef6170ca284d4102360242f4d007fdcdd8fcfbb90e7d9b693fb1101dec0fa152a7417f70003159ca3633299cae4035793aa7668df47b09e0fad406e278a6105bbd2b9a523c1a8fdb394b9de39d3d9e1ce9d9ba717014dbe59855a92ff2375a3a3477c8bd22cde51e5bbb738b92ef4f3781e605c24e7140b2504b59328cb8e20c5c5d19acca392bbf60194e6257f674df0f99945132d78c76f182f2eb52058a908abf568352d50a7aa4d061380cc58cea53f166a753ffc4a51e90a0f46104decd9eaa77d48300f2c7901465effda4fdb0e70f7ede3541890732d4ff10eef7745ca362eb336febc2609f50f237eac6d4950593bfefe0718ae3bbf227ddd524178b39ce4341e68e4c1e5c65b506b73965c5e6ba8e7472d3b573d41b4e458c97d1f0164376cb24fdc38bce00df871938e65f46c3df4fc20e574581d6631d759c316af7f7709e05e9dc465b87234029ae78f071d892d5e7ab7fab90cbaba55acb3e654a18a5f0bf79d6e471d53b5fca51085a65534dbfa953379c4d4a0022f03da76fce767cfe2930992935ea897fc56dc23d377004d119c9b648986e402b035b7927e567db9019c915c0ab54e6e45435336e37d974a7ea3dfad73915badda2e0c32b87391e3226ef0509ec6a33462a246e62e0fb83065db0270c6c026415dfac7be0e7b1e790631347665e789ce6be41e7ea32b987465ca6a803508a52626d92858156920f841da0532854cd5c966f02911d10a4e12f687801d7b87891e0d7a1ed0279e3cbea3d73b3886e798d39460ef71ebafd803e3d367a0c67c31d502021a796e6c351caca55865902dea97edf28ca7f4da37d62e17df5245e52510e1d5bac6851e1a2bb2228aeb6add3c07bad5798176145d1b46d5ae3169581f2286f6ca3b09ce4c44df0031d6ed077e6af6226b6e21634037079331094fd3bcd0126d5c88069d1c240eba9a4ef943552dd69a2786301a0d94ba5f4afad155583d81cae6f68e600979674d05c5593ada14dccf11745118dfb6da366a15655469cc0fe0d31cabff9a84e40896f8726bb64bb0c548b8b7a7c031967ef8a38e85063eeeb48d271aa893cda1c66204cd3b2c35e27fa7dd972bc396283e24671b9f4c1bd9a4dcf30c8887864305b3f92ec1e678f85d552d411f8c2012bc77ae55d6d8a7c31bb6a9b80a530ef2900961a5c59fa0716f5b6ac2aa5b2313b5539414b2abb7ea3f7b4044e91e463f02e9c51891458084782209323df56148ed89c83d2fc194c127e47ae5bd711f5b130e6b21775090c6156cbe9737b33865b48489f4533945c4b9491add986d3095956796c1b217bf6b09ec63958fca7a9ec6b5435bb3fdbaca8a707c37ba79098c47cd9208351b54e292509d4bc33bf40eaac6caa9f94d0918a7461e6bb8e8b259d3d90d641dec6612dc14b683ac4cbc217f6d108f666e66817867c70f3550d1ce37daf358cce35b8231fb70a4b1e302718163e5a628e8f653eeb25041290ef5f5289ec33dcec3bece209afaf2c4c8ed6145768ac945034473b01b63986f9882514722dd85df95448be18a59c5408ec8c95d203e7a4aebc68999c760d3f3929d0d28f7d8d0ea7c02a813515c5a82fc04cdcf20654c91af430aa34859a77eeca938842600afc6035605a0a9c01acdb164f2b2c3d4d7534c5292d08edb1adc446fedce1a14b7defb274851614de5157e8b5864f7ad8bf6d2f98515c07171afbb8c9d29a2202087bba880441bf68084d5bfdf3a7926ea2767a24bacdd5a6b98080b044071b3c21854333b84156771bbffe0458aed18e110ee0ec37f542b53afd04b76bbce6653d49434f0a8fe97d11cca1b211922bc48b0fa7526693889d0ae2b5a5f7746bd20803db5c57563137910efe92c6f4e0417978ac3af913d46fa9d49acf5f84de8e67f90b409bc78c30b58913f0149eab1629c1e8409190894f2591e208f3b61ed699670de4621675e9ca789cadb219013682d0655b785065dd4d2193f0a81b84f27330aa7a06fc09979239eff65b0327bd7887dd671bc4a51ca7dcca404fc24699a7703bdb1fe4b5175760f682531523ed75396e556b391b627035bbd9e323a004ec1875771b72f02af7711046a16e1df4fe22c8cc064bef1a401a430d2ed959aae3ab82db7a86b74821ed07dcf98ca76070b6e18fc749ef2ffeeec9585bd21aedaf8c05918bfd2f9ab1e1a6f023c0f2a2a418f5ecf711526525a165652eeab3ae16405ed177706844d1ca239f52641e0a66d89565d0b83cedc51d339bcf56ca21203fdadafb447c0e337496b2c5318cd5f44e6122c617387f85c3a6f76dc4d437e45f790c5f489bd56e56b8fa1e3111806429cd4ccf871b887ab9d8ee379f4cdd23bdbc476428ff912adcf7a84810c81943a778e57bbc3690911b5e046988dc85b7ccd09b7fc061f9259369601252aaeb4863d8d57796f1f4518130c911d1a331953663ef8a80fec491308297ccea77691fe14820aca10c6719c205988802791a54348222d6a34d9bf656696f396b27cfdea9d5b0e36838640d68ebe3be9ad72450232b66a5db274087e7a350a7d6abd95adf2557ee93154a966aab798b45c2fb1d5fa1f92db67a5bb2819e580dc15955249065189e4d1621c4517a67a76da14090a90b4da7272f57acc4228b49a1e5dc30002c11d03df9b60c382c026fac97ca1e389d6bb2af95494c2775b789988860478cb1e0a0e8e6a5b823fcaf6f8a031983408624a301bfad96784c9fe217e0c656cff8b65b3897a966c5ab572d269e30124ee813ac08ecec1aa40b73a3149e0647a00c612c0910878a079b5c163029435356473beced7fbc6ded2ee3e313082501fa91dc3ff05e4be525212ab350dceb9ac95c4f1db5399ea008b8609cb0c0f1a1319b9de77bbff478c197b9318005cf401a84f49499808fc403ea3ff9e1874d5ebe7997a0c03d977542c1877348da98f1d05641c9debd0dbba6b14ce8a83ac11de52ba7451cd1bb75f58ecc32676b3d00a76ce09e5695380ecc2e73f44ece11f77238d39696572e46761c7d5e638e94693591b70fffd8ab98b3294fc2614e3ce31424947d0515baeab18ca4a23d479fa0a55d2950082cb770dbc34e138e9469f218a657dcdfee84cac9131cf6ad38000630aaf3fad747cb1dfc777188bafc927e7371ae2be48772afc09b7937784c8365c0ac6caac7de7ede4202ba8d28b18e6d20a217c30776f97546dc65822ff02be3be42f6043f828927ddcd693a7b691f9312aed70b5346cab9ff0d21e8783677bd71cd1b5e4975e588e121a90cdb6b4d3219effc8a868dd110f5cdfc119c121c84c2ad04189f84cec8f7d98d71ebb1f9793af002e2d645d7cfc03e3a4f61c28ff69f08024a93b8c712df64c83859374ae6d5575048d7baa3a0fab0ec0ecc731e3523d9deaebed7de16e9c6c453093de8738f8d7f4a244a6f15432cb494855c6c9b840d514af760c73b88099a66fc926b2f05befc766729f109ea436bbbb5ce2513fe654d7e0b379b49ed555cbddb8a690132417a31f48e530449ffe71d1f851acb1bdf245ec02dd39925782511c0d8930f17a14c54906d96a2daf27144914135cef344451982b50c71c1e5bf7d63f646fbdb749e2e9ce8e84ed334fb90d9ab7c6e7b265bdff840606ec572b035877e7d18cad3fa246ed000ec243d38da351fbea47a54dbea0942fbbf3fd9b00f19c21417159eedf477eb6af4ea228cde4ed64cc2d6890db81c74e5e08720dbea0f5364c1923cef7e0a883188a99896483d2977646bc9ebe9c8667fa68b3aa9cd961ad1dcaeba799eec564d20d771390c2ea12eb8cad0575d08320515c790155dcf477952c72c536e1bb2d6bdca553b02d23992129ce65d520c9f38bd385e37b98ac6c6974bd1fce4d53a7d11666ab3c04b6ff39f93ea50790aa027062d99c1486c5c692eefb05c29737b178526c91b62595f79396d40f2558148dd72652806ffd9fb334e744a2025070780d684dedb6db564fc76a5cf6f75766806e5c644bdb58c6c2aefe02a523f676aef200a3ea928810be43ec4367ec203edae43eedecb608cc48cde469217e36002b8419ba55ce00044a6d3590ba22c77001347c1545d07486d6a5f70ad9561fee62ee4eda80953218711d68ead9b38f3ef1012a952a572b38a5c90536754717799777574874b45e0b39e938ab2d31823bb1f44f965e225be271b69a9ccb32da2df01c65401df771f5e3e195ac977e627e3c4b522928d95391c1f6869ec2e340caf3f336e246d042da8fbe9702980babbb45067d82abebdfe34e3832c123575c479b66a33e22e47a5d8f7ee3c40fb538a3bb7a08ec13017f4c58f7ef769b7597f7252c8b6d0e4bbcefe0e32b4c1c92c5da2506d2be19bb6f71e662fb81f016404c96c50e4ad61dd3ba73746ce0489136d3b0414992f506900151bfbdf118a0e2f998f893560225da2c19280238cab9a986c747a265b22c0d6473f8248f83a3e155f4ee67cbde536b3c4dce586cc8d8ea15e55f3569ede91d29f9fdbaa88d20909f3dc3450e22ddb91722ed6e42f515db47259b74e25966408f4cab33177a74a038daf0967864330fc0be9f1f2b685cfa288bf89e72fecefca841fd0564a47826e586b6d4eb8dacbbfb0808a3255d5f69a8c56ca6e17f2041eff85aaa4eac86c1008d428d91237ec5e2cedad5383703ea7ca8e7dfb483ffd8e1f2abe1a90af170660f881f6cac3025087d72b6454bbc3f8b7308a27ee8a6e8294955903b0a69f66dbb4b6d7dfa2e726ebbdf91908990b042bd09ae9a6f6cd39a4d626f62b2efd8e85c02adeb492a9c97a4e883cd2660b570d0cf5b13c60fb58d60f07ca43b2b3a21843f85801c8d824d2bee451b86db0a61b45142a397372a3deb3bc10d80bf4f9907f5f3200c65f9cb6dd6411284ad5f7b837cb121c42b99f1e517569fc12b2606cb3f45daa0597a8aec824bfd4a31e4b17d5715ec48e8b9e666a5a9f881884b5d06cad31f1830d76db5bae7ef1833b727f6a15c0f32b8e561b41d4f286c74c901201ca52b95dd2b7bc930f5c7702eb282f4dce8dbb37f5137996967a07b0131da890e27edbbf5f5bcd3885889277d6faca161a138460fd1e70ef41179389c87338eb9eae94f2b8167e7e0683836b6153b7428ce1969da01b096eea0b4e7d5d85bb96037c17ee9ca630921367f17eb83845264fec0ecc866e58f845f2f32be57ea9d5c2c595f82efa6608c4c8946f0f56f3856fdaf3b8c0f78a017604521c727a136c2ac28c16ae19da2482c199eb7930fda5198f8269c774b8b2bd769c377a6f86416c2c3579e57a329e74021597aa1ed4e6da50806bdbdee831101cfa13b97e99fd512e43fa414f7b4cf1262c16b9e30ac4c34b108355ac16b6053751fb8c2f4eb4bbf7edcfbd0184f2250344e47bbfe9ca50f0e91e65c78270c58603c20679d739b454d1ec3301fd6b884d00d7539bdd3178126aca8ae37b9d8ecfcf14e62e653864d3ee4f1fae9ffb2197ed8a2455c90359b6a09910b79c2822f04bf07b6a27e01c9f1883fbcd08b7c26d7c8c25271338914cbc157dbbd0efada31709841831c71c1aaf111d0d46845d9aaeb7249dae34fdb050047ac38fbf0b746f33d6ea0baa5d4f7ddadeacb5831b7f9d5e219e4bae55d0b8594f52f0011badef967afef02884ce212c3341c340ee8fdca78e887b7bf2a98c31d1bb8a3969b8b4c939c362cd3edc19598fae9ccd82c88aabbad4c4ae278aa1b59d2003375cc932210f4a636af6c3126f200c8a7ac82d8226f244661ac6d73aa76edb53fa5b2216f645e873de27fbf580c7148fa72f992a220d1d4f499779e25c8b996c580a1165848d23088a6369957841653e291c7f520a8665997bf958ff7da53bef74eea85e3a1a3657945513137351cd4aab8499f23718abb8f66dd7d60e9775639e32ca1e8faacdb8f6b66d0b1b714af355773f1aed034f2e4cdaa17bac308dfd889bf123762b5c894de392a3081af84195438fdfd1868e2d978bf3ec1df5e81b9f8f6afdfbe3dc344f2a6dbf550080e403690d2ca7cfc0244014939aa79a8b3a0933e2bbc226385e3e4188a1ba2b37c34e02fd28c31f2c48d1a83294da501ab012d1d5e5fd26cd41ee71b4a150cf784486f9f6b5ab510cf07cf9792dd9e4d8bf48f06464fc957885d346fc501f21a07ac7fc71b9c01519cf4d2fa766d15eaf459fc429ace3a1a61ba078da7324ac06e65d7f36271f6898e8ccd673edeb25571c44606d7bde39d5195472e727bc7e2a2d1578328cdaf90400a7843f31793ad33d0f32885bf9b1f0e56d4a3ec40a1094e0ecec32a1712b88ff3008213795ffece882254753011c6988931fc9f19b5ad0891e20887b47ccf460e303842bb4c0b62163868e805b3bae6e4937a476e7eafe9fde0d0cf62223f714c69be6833c10d06f91a78016b1c00087415ac4a5b7b5e10f98a3e19adf60d56d5bef918c1c7ebbf7cfc37130ffae2ad7a620250c7387069ecc926f34069b717b97bf2a0ef0a2bf796034e88d30aa4235744a1aa5601ba718add8cd0cf38411f4787cd22e21dbacd9e480b13af38477e70d2a4800f680fa7cc8684fd467b86555422b1a901144b03e4327b2573769cb02de90e8e30df7afd2e571e2946d23a0efe02bac8e9698d12589378e28d1c36ce328a27abff98eca7b6da95daa681700397ce62c9b50a47cedeafd51b62e953413639a9d9978fb3e1604027751da66b5e481ec1e4697d64a4477c67ec2967e2389b6f716f77c810a62a5fd78c69907f4a4dc210db30d5d4e9dd1a82c9ca1f0dbeecb33a702f4860426e7d1c26d1a00ee4c62e3d671d545b26aab8ac758c53cea2250ed929aa715bf513a5fa242b78ddbc263990c42025ba2a52e368f6a18e2cfc0a6047e7f0e7187c3e36d61905cf0cf824a08e5c240ec56b04c909390322ce24f35001e8d5a599ffadbe2a8755920cc488f40be225110310d4e9e4d4cfa34f953c6f6cc6a5f8a89373739dc5da9445947fb58bec2c8e5b7f8c349d6df29e6a87336dd7bccb036139922faf14f3eeb92ba12d0084b1da8d36a3f9656414c0f32a1b2575a5147568ad96c2125701fc67d00e9d78788bfd0188276727d568bb0800a576913dbc5c1035fbcaa5359bc9b7fca0ef528903250be1a942e59727789ec61ee1ae617c3a23d3a89044a9ec729ef0cf7ec6a3d01e06e864c2e24c38a8389826c2cd471cca5cfd18a34050f24b99dcd26d418465a5e3623d7c9dffe7e65fc25f90710f42d00fb81b33a2db18d0ff7955c8d87ba8fdfe1186b638312505c7810dd0ead9c7722fcef542d2a73f107993e3ec78d3a0b15506ebd4d13a72384f77268b44c32a957aefda0bed253e76cb09012f104bd0c1f04e96b1fc60d08eb79ce9216fe1fde6ffe65d09056c9643ada21ef080b9da75c10f71ad334e4d3b5d3a0e55bd1ffcc18259cd28f6bbdfab16575cdcce86c95f894cd001e795cdaeac95c90d1ba94806ea2fdf45906eb7a2ba0613503f7aa7397e78c964ad3251d297ea76d88b4221efccb2c", 0x2000, &(0x7f0000000d00)={&(0x7f0000000480)={0x50}, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0})

[  625.764334][T16132] FAT-fs (loop2): Filesystem has been set read-only
executing program 1:
mmap(&(0x7f0000000000/0xfbe000)=nil, 0xfbe000, 0xb, 0x31, 0xffffffffffffffff, 0x0)
openat$kvm(0xffffffffffffff9c, &(0x7f0000000140), 0x0, 0x0)
madvise(&(0x7f0000000000/0x600000)=nil, 0x600003, 0x19)
r0 = openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000080)='memory.events\x00', 0x275a, 0x0)
mmap(&(0x7f0000000000/0x3000)=nil, 0x3000, 0x0, 0x12, r0, 0x0)
madvise(&(0x7f00001c1000/0x3000)=nil, 0x3000, 0x17)
mmap(&(0x7f0000000000/0xff5000)=nil, 0xff5000, 0x0, 0x4c831, 0xffffffffffffffff, 0x0)

executing program 2:
getsockopt$EBT_SO_GET_INIT_ENTRIES(0xffffffffffffffff, 0x0, 0x83, &(0x7f0000000140)={'filter\x00', 0x0, 0x0, 0xe5, [], 0x0, 0x0, &(0x7f0000000280)=""/229}, 0x0)
syz_usb_connect(0x1, 0x2d, &(0x7f0000000140)=ANY=[@ANYBLOB="1201000009a65d0860040800dec30102030109021b050000000000090400000178eaf50009058402"], &(0x7f0000000080)={0x0, 0x0, 0x0, 0x0, 0x1, [{0x0, 0x0}]})
socket$kcm(0x10, 0x0, 0x10)
bpf$MAP_CREATE(0x0, 0x0, 0x0)
pipe2$9p(0x0, 0x0)
preadv(0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0)
syz_open_dev$evdev(&(0x7f00000000c0), 0x40, 0x0)

executing program 0:
openat$nci(0xffffffffffffff9c, &(0x7f0000000080), 0x2, 0x0)
r0 = openat$rdma_cm(0xffffffffffffff9c, &(0x7f0000000000), 0x2, 0x0)
write$RDMA_USER_CM_CMD_CREATE_ID(r0, &(0x7f0000000340)={0x0, 0x18, 0xfa00, {0x0, &(0x7f0000000380), 0x13f}}, 0x20)
write$RDMA_USER_CM_CMD_CREATE_ID(r0, &(0x7f0000000100)={0x0, 0x18, 0xfa00, {0x0, &(0x7f0000000080), 0x2}}, 0x20)
writev(r0, &(0x7f00000000c0)=[{&(0x7f0000000080), 0xfffffebe}], 0x1)

executing program 3:
r0 = syz_open_dev$evdev(&(0x7f00000000c0), 0x3f, 0x822f01)
sendmsg$IPCTNL_MSG_CT_NEW(0xffffffffffffffff, &(0x7f0000000040)={0x0, 0x0, &(0x7f0000000000)={&(0x7f00000001c0)={0x18, 0x0, 0x1, 0x0, 0x0, 0x0, {0x2}, [@CTA_TUPLE_ORIG={0x4}]}, 0x18}}, 0x0)
r1 = openat$mice(0xffffffffffffff9c, &(0x7f0000000180), 0x0)
write$char_usb(r0, &(0x7f0000000040)="e2", 0x918)
unshare(0x60480)
poll(&(0x7f0000000200)=[{r1}], 0x1, 0x0)

executing program 4:
r0 = syz_init_net_socket$nl_generic(0x10, 0x3, 0x10)
r1 = syz_genetlink_get_family_id$netlbl_mgmt(&(0x7f0000000040), r0)
sendmsg$NLBL_MGMT_C_ADDDEF(r0, &(0x7f0000000100)={0x0, 0x0, &(0x7f00000000c0)={&(0x7f0000000080)={0x24, r1, 0x1, 0x0, 0x0, {}, [@NLBL_MGMT_A_PROTOCOL={0x8}, @NLBL_MGMT_A_IPV4MASK={0x8, 0x8, @dev}]}, 0x24}}, 0x0)

executing program 1:
r0 = openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000040)='cpuacct.usage_sys\x00', 0x275a, 0x0)
write$binfmt_script(r0, &(0x7f0000020240), 0x10010)
mmap(&(0x7f0000000000/0x400000)=nil, 0x400000, 0x7, 0x10012, r0, 0x0)
r1 = socket$rds(0x15, 0x5, 0x0)
bind$rds(r1, &(0x7f0000000840)={0x2, 0x0, @loopback}, 0x10)
sendmsg$rds(r1, &(0x7f0000000000)={&(0x7f0000000040)={0x2, 0x0, @private=0xa010100}, 0x10, 0x0, 0x0, &(0x7f0000000780)=[@rdma_args={0x48, 0x114, 0x1, {{}, {0x0}, &(0x7f0000000080)=[{&(0x7f0000002640)=""/102389, 0x18ff5}], 0x1}}], 0x48}, 0x0)

executing program 3:
r0 = openat$dir(0xffffffffffffff9c, &(0x7f0000000000)='.\x00', 0x0, 0x0)
ioctl$FS_IOC_FSSETXATTR(r0, 0x401c5820, &(0x7f0000000600)={0x23e3})
mkdir(&(0x7f0000000040)='./file0\x00', 0x0)

executing program 4:
bpf$PROG_LOAD(0x5, &(0x7f0000000200)={0xc, 0xe, &(0x7f0000000380)=ANY=[@ANYBLOB="b702000003000000bfa30000000000000703000000feffff7a0af0fff8ffffff79a4f0ff00000000b7060000ffffffff2d6405000000000065040400010000000404000001007d60b7030000000000006a0a00fe00010000850000000d000000b7000000000000009500000000000000496cf2827fb43a431ca711fcc9cdfa146ec56175037958e271f60d25b7937f02c8695e5a1b2cdf41dc10d1e8bf076d83923dd29c034055b67dafe6c8dc3d5d78c07fa1f7e4d5b318e2ec0e0700897a74a0091ff110026e6d2ef831ab7ea0c34f17e3ad6ef3bb622003b538dfd8e012e79578e51bc53099e90fbdb2ca8eeb9c15ab3a14817ac61e4dd11183a13477bf7e060e3670ef0e789f93781965f1328d67049047be0002476619f28d99cd0aa7b73340cc2160a1fe3c184b751c51160fbce841f8a97be6148ba532e6ea097a75dfebd31a08b32808b80200000000009dd27080e71113610e10d859e8327ef03fb6c86adac12233f9a1fb9c2aec61ce63a3462fd50117b89a9ab759b4eeb8cb000067d42b4e54861d0227dbfd2ed8576a3f7f3deadd7130856f756436303767d2e24f29e5dad9796edb697a6ea0180aabc18cae2ed4b4390af9a9ceafd07ed0030000002cab154ad029a119ca3c972780870014605c83d7d11c3c975d5aec84222fff0d7216fdb0d3a0ec4bfae563112f4b391aafe2348754000000000000007642d3e5a815212f5e16c1b30c3a2a71bc85018e5ff2c910496f18afc9ffc2cc5a788bee1b47683db01a46939868d75211bbae0e7313bff5d4c391ddece00fc772dd6b4d4d0a917b239fe12280fc92c88c5b8dcdcc22ee1747790a8992533ac2a9f5a699593f084419cae0b4183fb01c73f99857130665b6341da114f08cd0509d380578673fffffff7f23877a6b24db0e067345560942fa629fbef2461c96a08707671215c302fae29187d4f5c06a960fd37c10223fdae7ed04935c3c90d3add8eebc8619d73415e6adcda2130f5011e42e50adab988dd8e12baf5cc9398c88607a08009c2977aab37d9a44cfc1c7b4000000000000fa47742f6c5b9c4b11e7d7262a1457c39495c826b956ba859adfe38f77b91bd7d5ca1664fe2f3ced8468911806e8916dc15e21644db60c2499d5d16d7d915836ab26c169482008ef069dc42749289f854797f2f900c2a12d8c38a967c1bbe09315c29877a331bcc87dc3addb08141bdee5d27874b2f663ddeef0005b3d96c7aae73835d5a3cda9e90d76c1993e0799d4894ee7f8249dc1e3428d2129369ee1b85afa1a5be5f6eb2eea0d0df414b315f65112412392191fa83ee830548f11e1038debd64cbe359454a3f2239cfe35f81b7aded448859968ff0e90500d0b07c0dd00490f167e6d5c1109681739dc33f75b20428d6474a0a91ee90b8de802c6b538622e6bbcb80f87b4150900000000000000f75409000000000000001d695c4559b82cabac3cccadc1e1c19af4e03020abf5ff0433d660f20898d2a045d009a0ffb20a77c9af2b80c05184a66d30bbea2ca45a4d6d6d1e6e79aef42355a500587b603306a5af8d867d80a07f10d82eafb03062e95196d5e3ff010000000000000be959096ea948cfa8e7194123e918914a71ad5a8521fb9553bc60f7d9719b55b3abb6bba3d113a680a8d46fe074c83fbe378a3889e8145b2eaceab05ef932c6e4f8ef0ed0d818a7b76d839cf3c63ebb4380b168c38fa32e49563cfee3a7f0fc18bfa32c418cef875fb49e2989177a30280bc586e79a5dd8076c248e7d6e97b3ce267dd4e27b6ef206660090bb2164474cef378f97ca33fc03000000000000001547053453b6c9aec91a24079b21d52fb5516bf0c28ef37aa76442f6083dc99cd61afaf6be45d7b00d36397187820ba150979adf8e54dd05ddf2f10ac2d5c759c3e5468f5874c24411d415b6b085fb73a2c7c3852e0e658ffeb4e863428a792bee94f6cd895424360e0464f9d7ea425f2fa6aac029d15af607ad83532ff181c985f54b39370c06e63055b4d6a36fa98a44e379d28307c9912fb097601f3f88a2ca6fd1f9320cfe7fc8e9f7f15f02e177ce23f43a154b42e26f037e8a013709003f509e6e540c9ba9c2a589ac5d8ad67a65e9a44c576dc24452eaa9d819e2b04bdd1c000000070000000000000000000000005333c6199c12dcd926891927a7267ced1fc105dddd77ab929b837d54aa17eb9fbdc2bdc0e98ae2c3f23a6131e2879f04ff01000030b92dd493be66c2242f8184733b80ba28e8ffffff7f00000000bb2f89049c5f6d63d56995747639964217aacfe548bc869098aa0500e51dbc9e2d4db3c5f79fd355222ec2a00cf7f2ccd6dd6d2dc2a815d8314221a5472f1318a9dfbec5a759579caf3262129b14e99040b5d91398e17df85c25ccae973eecc7d187168d5c9cd848d566cc17587641ed01889c927da38d83314480b15e23138c5b877a72bd4cf74a299df4fbfc8e6ea96939f15d254d9033c5a45706bda78ab60200000000000000000000000000000000000000706f78f0a2ea9667fb5b951808545a46830970c2dfae01adbda7d29bf1f70de6f9d7150808ed086642e64ebf98762b34338b80e41b704c3eefaf0bb5f7d895de17a10b0a0ea15ccc0d7a830b6eb33b6b61675511d693ef5e3c44bbf71cabc5175d879e7499f8baae2a1a09cf38da73297764fbc0e723e1cc3abb12e3076982ed32c94a2ce3e6f37c47e983da4ca5c96187db5a2a2e1742bc93a65d7187126126b3a80f17dd2f7dbbe82d104ede9ba6925afc2ee6cb94f56f1363cad635abf8f983292c49c0ebf5005154c7b58a3a2a2e5a00d2f953a86d2fd92b8661264f781e3fb02d05a28f3f17b64d0258853d45cb5ebde10cd3d82eeed2f1ed925b7cf400304932c5ed0a362b235ce37e1f17700f7d1fecf8be8a2c5d25a9c60657560d05441387ff158a018d19a286c56d0886eb59d509ee89cc2df52881d005b2e5c27563ba54e4153c132d0366a9660000000000000009c1aaec93ec0f925921fb2e9eb202a29bef28224dbabe723de5c584bc398a8792e493048c87f60a51a391e95921218149403558fd13c649f90b0911d57eeb298b590581eba1ce383b539ab80fd15445987b1bb4eb512545e1ab65fef310e10b1ee362b51c72f82edf2f502ddf52567775e34a56d1be892f1e62b08950d517fa6fb1b0ef2edf1b67f8644786116b037d4a36fdd30b000063e58c856ec44cbbc2d370553f832af9480215e09aaa3843fe360b1c293a14627f2cfbe278f31d0abc0f5aaa10926dbbfe8a4b131c13a73d4e6d065c2c0fed3ab8442520ce0e0ad7d2d177377ab197ace3ef8b1c24ceb0bdee84bd6e6317633938dd19dc42de7f8f860eca6d9c74525fcd3497526df4c13e3ba5f0d75365a4542ae9440d2fede416d618cdaaf7e038879c5d177b3876fda4121e15a00adb976064a93e8d000000000000903350932d3eef7fdada20c19807066e2c72d0d816eb9fa50be213bf6bbb7ccb9f268a153e6ced68f192ebed6e86af0f2cec7335fa8039fd6eb025440bc2a34d071f0a0e6774308a2c5986aa9200a1306ffa5a71ca69e89a6980612b35fc858f37c2c398515a910a35e22ab0573c10b85df4c2972a2fb8b9c080fbb41a753791df727fdeadc5cf218a6eda31312256191c620cce34d1e3bf40a4a207ab1575b399eb8155781bfc7cb5920b49c039935a888d77041814f60fbbcafa487ee96b368e8769da90b44190e569fe8b1d155d0765baaca5c5548b5a78bb43e5d9e47a1d5809bb178184b5672d08e29aecf1f572ac1e6cab7e820751e95999b7532603494d37a2bff300"/2730], &(0x7f0000000340)='syzkaller\x00'}, 0x48)
socket$packet(0x11, 0x3, 0x300)
r0 = openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000040)='memory.swap.events\x00', 0x275a, 0x0)
socketpair$unix(0x1, 0x5, 0x0, &(0x7f00000001c0)={<r1=>0xffffffffffffffff})
r2 = openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000040)='memory.swap.events\x00', 0x275a, 0x0)
setsockopt$sock_attach_bpf(r1, 0x1, 0x41, &(0x7f0000000100)=r2, 0x8)
setsockopt$sock_attach_bpf(r1, 0x1, 0x41, &(0x7f0000000100)=r0, 0x4)

executing program 0:
r0 = socket$nl_netfilter(0x10, 0x3, 0xc)
sendmsg$NFT_BATCH(r0, &(0x7f000000c2c0)={0x0, 0x0, &(0x7f0000000200)={&(0x7f00000008c0)=ANY=[@ANYBLOB="140000001000010000000000000000000000000a28000000000a0101000000005e1affd5020000000900010073797a300000000008000240000000032c000000030a01030000e6ff00000000020000000900010073797a30000000000900030073797a320000000014000000110001"], 0x7c}}, 0x0)
sendmsg$NFT_BATCH(r0, &(0x7f00000002c0)={0x0, 0x0, &(0x7f0000000040)={&(0x7f00000003c0)={{0x14}, [@NFT_MSG_NEWRULE={0x5c, 0x6, 0xa, 0x40b, 0x0, 0x0, {0x2}, [@NFTA_RULE_EXPRESSIONS={0x30, 0x4, 0x0, 0x1, [{0x2c, 0x1, 0x0, 0x1, @socket={{0xb}, @val={0x1c, 0x2, 0x0, 0x1, [@NFTA_SOCKET_DREG={0x8, 0x2, 0x1, 0x0, 0x11}, @NFTA_SOCKET_LEVEL={0x8}, @NFTA_SOCKET_KEY={0x8, 0x1, 0x1, 0x0, 0x3}]}}}]}, @NFTA_RULE_TABLE={0x9, 0x1, 'syz0\x00'}, @NFTA_RULE_CHAIN={0x9, 0x2, 'syz2\x00'}]}], {0x14}}, 0x84}}, 0x0)

[  626.275070][    T8] usb 3-1: new low-speed USB device number 22 using dummy_hcd
executing program 4:
r0 = socket(0x10, 0x803, 0x0)
r1 = socket$can_raw(0x1d, 0x3, 0x1)
setsockopt$SO_TIMESTAMPING(r1, 0x1, 0x41, &(0x7f0000000140)=0x632f, 0x4)
setsockopt$CAN_RAW_FD_FRAMES(r1, 0x65, 0x5, &(0x7f0000000040)=0x1, 0x4)
ioctl$ifreq_SIOCGIFINDEX_vcan(r0, 0x8933, &(0x7f0000000880)={'vcan0\x00', <r2=>0x0})
sendmsg$can_raw(r1, &(0x7f00000004c0)={&(0x7f00000000c0)={0x1d, r2, 0x3}, 0x10, &(0x7f0000000080)={&(0x7f0000000300)=@canfd={{}, 0x0, 0x0, 0x0, 0x0, "621105b0ae0282d478b6b01305946c17afcea96765fbac1cd8aabe71d5522a79da5a1d57b5fc633203000000ab6e543a04aa00"}, 0x48}}, 0x0)

[  626.447431][  T957] netdevsim netdevsim0 netdevsim3 (unregistering): unset [1, 0] type 2 family 0 port 6081 - 0
executing program 4:
r0 = openat$cgroup_ro(0xffffffffffffff9c, &(0x7f00000001c0)='pids.current\x00', 0x275a, 0x0)
ioctl$FS_IOC_FIEMAP(r0, 0xc020660b, &(0x7f00000008c0)=ANY=[@ANYBLOB="0000000000000000020000000000002001"])

executing program 0:
r0 = bpf$PROG_LOAD(0x5, &(0x7f00000004c0)={0x6, 0xb, &(0x7f0000000240)=ANY=[@ANYBLOB="18000000000000e50000000000000000180100002020702500000000002020207b1af8ff00000000bfa100000000000007010000f8ffffffb702000008000000b70300001e334185850000007300000095"], &(0x7f00000000c0)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_PROG_TEST_RUN(0xa, &(0x7f0000000640)={r0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2}, 0x50)

[  626.647617][  T957] netdevsim netdevsim0 netdevsim2 (unregistering): unset [1, 0] type 2 family 0 port 6081 - 0
[  626.647857][    T8] usb 3-1: config index 0 descriptor too short (expected 1307, got 27)
[  626.719995][    T8] usb 3-1: config 0 has an invalid interface number: 0 but max is -1
[  626.745918][    T8] usb 3-1: config 0 has 1 interface, different from the descriptor's value: 0
[  626.779334][  T957] netdevsim netdevsim0 netdevsim1 (unregistering): unset [1, 0] type 2 family 0 port 6081 - 0
[  626.780863][    T8] usb 3-1: config 0 interface 0 altsetting 0 endpoint 0x84 is Bulk; changing to Interrupt
[  626.864250][T16161] loop4: detected capacity change from 0 to 4096
[  626.907884][T16161] ntfs3: loop4: Different NTFS sector size (2048) and media sector size (512).
[  626.952688][  T957] netdevsim netdevsim0 netdevsim0 (unregistering): unset [1, 0] type 2 family 0 port 6081 - 0
[  626.981769][T16161] ntfs3: loop4: Mark volume as dirty due to NTFS errors
[  627.085346][    T8] usb 3-1: string descriptor 0 read error: -22
[  627.096013][    T8] usb 3-1: New USB device found, idVendor=0460, idProduct=0008, bcdDevice=c3.de
[  627.116895][T16151] loop1: detected capacity change from 0 to 32768
[  627.124601][    T8] usb 3-1: New USB device strings: Mfr=1, Product=2, SerialNumber=3
[  627.149881][T16161] ntfs3: loop4: ino=21, "pids.current" fiemap is not supported for compressed file (cp -r)
[  627.178506][    T8] usb 3-1: config 0 descriptor??
[  627.197200][T16146] raw-gadget.0 gadget.2: fail, usb_ep_enable returned -22
[  627.215905][    T8] hub 3-1:0.0: bad descriptor, ignoring hub
[  627.221880][    T8] hub 3-1:0.0: probe with driver hub failed with error -5
[  627.231176][T16151] XFS (loop1): Mounting V5 Filesystem bfdc47fc-10d8-4eed-a562-11a831b3f791
[  627.238005][    T8] input: USB Acecad 302 Tablet 0460:0008 as /devices/platform/dummy_hcd.2/usb3/3-1/3-1:0.0/input/input24
executing program 4:
prlimit64(0x0, 0x0, 0x0, 0x0)
close_range(0xffffffffffffffff, 0xffffffffffffffff, 0x2)
timer_create(0xfffffffffffffffc, &(0x7f0000000140)={0x0, 0x12}, &(0x7f0000001400))
timer_settime(0x0, 0x0, &(0x7f000006b000)={{0x0, 0x8}, {0x0, 0x9}}, 0x0)
syz_mount_image$vfat(&(0x7f0000003880), &(0x7f0000000000)='./file1\x00', 0x40, &(0x7f0000000180)={[{@uni_xlateno}, {@shortname_win95}, {@shortname_winnt}, {@iocharset={'iocharset', 0x3d, 'macromanian'}}, {@shortname_lower}, {@shortname_lower}, {@utf8no}, {@utf8no}, {@fat=@nfs_nostale_ro}, {@fat=@uid}, {@rodir}, {@shortname_win95}, {@shortname_winnt}, {@iocharset={'iocharset', 0x3d, 'ascii'}}, {@fat=@uid}, {@utf8}]}, 0x1, 0x2a9, &(0x7f0000000480)="$eJzs3c9KM1cYB+B3YkzSdpGsS6Gz6FrUbTdxoVDqqsVFu2mlKogJBQXBUhpdddsb6BUUCt2V3kM3vYNCt4UuhQpTJpkxxiRT82H0+/B5Nh7PnN+cP45kIfP65Xv9k4M0jq6+/TNarSRq3ejGdRKdqEXpMiZ0fwgA4E12nWXxTzaySC6JiNbylgUALNHU53+SVAd+eZp1AQDL8+lnn3+8tbu7/UmatmKn//35Xv75n38dXd86iuPoxWGsRztuIrJbo/ZOlmWDeprrxAf9wflenux/8Xtx/62/I4b5jWhHZ9g1mf9od3sjHbmTH+TreLuYv5vnN6Md/07MX/6BYntzKh8R9c7k+teiHX98FV9HLw6GixjP/91Gmh7/Vp5Ink8G53vN4bixbOUJfhwAAAAAAAAAAAAAAAAAAAAAALwQa0XtnGYM6/fkXUX9nZWb/JvVSEudyfo8o/xttcB79YEGWfxY1tdZT9M0KwaO8/V4tx7159k1AAAAAAAAAAAAAAAAAAAAvF7OLr452e/1Dk8fpVFWAyhf63/V+3Tv9Lwfcwfn0+w3x3PVimbFnWOlHJNEVC4j38QjHUt14/LirXlr/unninhrVqr1/5OuVp3P4zTKp+tkPxmdYXJvTDPGuygav969TyNOz7KHzNWYdylb6PFrzLzUXnjvjXeGjUHFmEiqFvbhX6OTK3qS+7toDE91Zny1aBTx2tTT28p7GvPiU78pUxLVOgAAAAAAAAAAAAAAAAAAYKnGL/3OuHhVGa1lzaUtCwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACe1Pj//y/QGBThBwxuxOnZM28RAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAF+C/AAAA//+zK1UG")
mount$9p_fd(0x0, &(0x7f00000001c0)='.\x00', 0x0, 0x804020, 0x0)
r0 = openat(0xffffffffffffff9c, &(0x7f00000003c0)='./file1\x00', 0x1c5002, 0x0)
ftruncate(r0, 0x0)

[  627.274877][ T2922] ntfs3: loop4: ino=5, ntfs3_write_inode failed, -22.
[  627.367838][  T957] bridge_slave_1: left allmulticast mode
[  627.395288][  T957] bridge_slave_1: left promiscuous mode
[  627.402111][  T957] bridge0: port 2(bridge_slave_1) entered disabled state
[  627.421016][  T957] bridge_slave_0: left allmulticast mode
[  627.434804][  T957] bridge_slave_0: left promiscuous mode
[  627.451986][  T957] bridge0: port 1(bridge_slave_0) entered disabled state
[  627.476113][ T5108] Bluetooth: hci2: unexpected cc 0x0c03 length: 249 > 1
[  627.477201][    T8] usb 3-1: USB disconnect, device number 22
[  627.489549][    C0] usb_acecad 3-1:0.0: can't resubmit intr, dummy_hcd.2-1/input0, status -19
[  627.515500][ T5108] Bluetooth: hci2: unexpected cc 0x1003 length: 249 > 9
[  627.532954][ T5108] Bluetooth: hci2: unexpected cc 0x1001 length: 249 > 9
[  627.553952][ T5108] Bluetooth: hci2: unexpected cc 0x0c23 length: 249 > 4
[  627.574568][ T5108] Bluetooth: hci2: unexpected cc 0x0c25 length: 249 > 3
[  627.585074][ T5108] Bluetooth: hci2: unexpected cc 0x0c38 length: 249 > 2
[  627.599019][T16151] XFS (loop1): Ending clean mount
[  627.616513][T16173] loop4: detected capacity change from 0 to 256
[  627.658649][   T29] audit: type=1800 audit(1715377307.184:982): pid=16173 uid=0 auid=4294967295 ses=4294967295 subj=_ op=collect_data cause=failed(directio) comm="syz-executor.4" name="file1" dev="loop4" ino=1048774 res=0 errno=0
[  627.686087][T16173] FAT-fs (loop4): error, invalid access to FAT (entry 0x00000001)
executing program 4:
openat$iommufd(0xffffffffffffff9c, &(0x7f0000000000), 0x0, 0x0)
openat(0xffffffffffffff9c, &(0x7f0000000040)='.\x00', 0x0, 0x0)
openat$binder_debug(0xffffffffffffff9c, &(0x7f0000000040)='/sys/kernel/debug/binder/state\x00', 0x0, 0x0)
r0 = socket$can_raw(0x1d, 0x3, 0x1)
ioctl$ifreq_SIOCGIFINDEX_vcan(r0, 0x8933, &(0x7f0000000a00)={'vcan0\x00', <r1=>0x0})
setsockopt$SO_TIMESTAMPING(r0, 0x1, 0x25, &(0x7f0000000000)=0x3cca, 0x4)
sendmsg$can_raw(r0, &(0x7f0000000340)={&(0x7f0000000280)={0x1d, r1}, 0x10, &(0x7f0000000300)={&(0x7f00000002c0)=@can={{}, 0x0, 0x0, 0x0, 0x0, "d53495ed19ac6f39"}, 0x10}}, 0x0)
socket$igmp6(0xa, 0x3, 0x2)
pselect6(0x40, &(0x7f0000000600), 0x0, &(0x7f0000000680)={0xff}, 0x0, 0x0)

[  627.716663][T16173] FAT-fs (loop4): Filesystem has been set read-only
executing program 1:
bpf$PROG_LOAD(0x5, &(0x7f0000caefb8)={0x8, 0x3, &(0x7f0000000240)=ANY=[@ANYBLOB="850000004f00000054000000000000009500000000000000ef0285b73eae795b05ad261777db75186baf0b2792ad03f20472662181fe046096c5df696334e2d836395560230500ef286f21c974d520c247fd200851f90b2dd5e5f6b23909a23ee27007dae2a0fdf92809a931196df3be84781f7ecafaf33acf7e01a23999fdfb4b490f6cfe5edf2740576acb262e0de2b8e288a85dfe7c79e969b738dbc61171dfd8f5e33fbf1ee05bc5bdeb164dc2058455e3ba438c9109dd001ad93df3fc235bed50ffce5ea79cfc80f7d53ae51691362ba21394bd614ec41f636ec0e299e370f5631acfab5a6519a36f963679457241bc21ecdd1ee2b9b7ae315e5b515c71c39bf4b45f5e3f7cd3f6404fc93cf55149f0c3a7b87f86120153725784e98975e8617ffc7e8cc497f43789f5208fd84f2b34f7853d9c52848dd17c5796b3cdf2527d7929631cca05e27c28566d2c47699bc6c3f5f766c3cb8cd6a4a446936895dc5b44d224a0b3c2ca8087486aead1d034d98832ad677b28b10ed58f8de2d5ae49ba35be16888ea8da9bf33f91a6c5056af135b53e191b0dee15f0d8ab12abc04eedfeb65355400900000000000000b4717107bf564a2350564f5ef2bb8e9274d5d40af19b0afe0c774b562378fc3dbf8be42828b4cb3d6cf6930f5c4c71563e4eb0d341dc742b00802b498fef8490b52ad11085ce4a028c7af46774b391e2124fcd93ff05ff1ad0da384ff0801734c58aad0eba11e3e817c3b651bb99090189ee00012f89e6b5ca8e62a5f5ff0dc6ed83392fd551d0eedc496037c1de1b3df83509d2fa1023eb77b8a13de09e22a7f19088bcbd8f47ad5a964ab6bbb94784d31b397229ae3fb66ffe0e9913d32301c844e58f000096f5766dc1ca5e8cfee332a288090000008000000000cb88186bcd36a2ecce33a3048f6f97e14dac56e84aba0bdee2bcd21132632905c060b3aca1d4446f456e2088e7257d575e8465d7ed767e415a826d1458a32e904a1ffaf090c2884d4a56958ab143cdb95b6c39e04010b888bd95b09d50d7e6c5c084aa8cdc21890b000135d28f977ab43670412afe8361b60bf37058fdf9cdf22d8da0f2d1cc813cad61011e3060badbe396b3fb928c0500000000000000770e11c5043535696289b227c6b313e2852c52f9975cd124771bef02f431afe50e0000df13ec1a2ba3e4bc7285bae2b98955a30dcc99ae25a56898b95424c20dfe77c34000000073830d7deb2aea80972cf5a7ba0347a4a7b9ff7c1d17ce2dec87fe9922aa04cf47002515c36ac646da6783135f5de53354ea5e160d0703b3d6412e5f3ce9c4a43b9bc19edea4bf8f4f3f33b80242aaabec9a82841aaf132876d366a145ec4161e7c45c397a1aa7a1126f6bc9f55b33a00c542083c22308b7eb04e4c969084c65a15cdfdfc54b1bd9825922c55a2c08a7380b7540e5e2af84f3bc6c5497cae5d43da03cccf136a825e8bc9416c1e38f321970ecca2b481c919c87c2261b896f739ea9d4c4b86947b6ccb0b02c7000bb6572089490df75b1a2ee38c2777a6a4e1e9778a141021f07bdcb3d5e5aee5139daf619ae84a79fcf6b55ff211a58af84ffa9fb8511b3fe7413132cc1750000000000000000000000000000000000000000000000000000000000000000000000001ce5e69e6d5ca2ab36012fd18f46de6c2bf0aa041a54026a2d3ad82bf89b402bd6f50d9779b4279d8301b626a1a2451f6e1f3672e1524e79bf7948f9b4a7c16ad30642aadb84fd7b3805dd38f32e74ff4a55554fa8f522dc7ba39d2034ab057f8e0b6b9d680cf775014ae2c8603b36d14d557b9c40869d6b7d8b46943458fe0dacefb875b80b5ee2411f285bb532749aa0503c6e3021012e1b9e4daee9368c2b9f0c6b4cddced6e665a71830f582f6cc2b25818082e37b364b1b1113ef8fdd1461a2afd8c752aa116cf7d9934be7118a2fb89b16e5900eb82dcf4cf300000000a49ac51a898d0000000000000000000000000000009c82049f390cb8b5003c089357aae80aeaa209de7a94e8ddcd36580673c74fd78154e314a522bb2dd191ce0000000000000000000000000000000000000000000000458d3a1aae1b853474527c26f2ae88b9bc50a078e7e4ed4901da8c75e7131286a7c3edec17b33000954d89621f463836ca8b83e937155ae7fa35b77bd3b44afdba4fba6c20c3bfe518c1de4c5f414cb99f0a18d643214b0824b41f034f3a7bdcd413e519c2b2bd7bffe11c2a625feae36b1f37cccdc8f19a4fb67620002298dc582825d867df5e5ef6e69978f63ea07e4fa6f3d4fd603dfff1d6dd366ca484cfcfdf4daebaab16cd068be95828a5f68373d24502d8801186188fddbf22939ea9562c499fa8f899d60dbab3da91f692570cd98d9367fa13926b0fd57399014bdb6e79626cfc0ff5dac7e7e202dc1b0b3faff2749db54ad9690f7a41aed7aa4dfa"], &(0x7f0000281ffc)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x8, &(0x7f0000000000), 0x185}, 0x48)
r0 = socket$inet_udp(0x2, 0x2, 0x0)
bind$inet(r0, &(0x7f0000000000)={0x2, 0x0, @local}, 0x10)
setsockopt$sock_int(r0, 0x1, 0x7, &(0x7f00000000c0), 0x4)
connect$inet(0xffffffffffffffff, &(0x7f0000000140)={0x2, 0x0, @multicast1}, 0x10)
sendto$inet(r0, &(0x7f0000000100)='J', 0xfdbe, 0x4004084, 0x0, 0x11000a00)
socket$nl_generic(0x10, 0x3, 0x10)
syz_open_dev$tty1(0xc, 0x4, 0x1)
ioctl$KDFONTOP_COPY(0xffffffffffffffff, 0x4b72, 0x0)
syz_genetlink_get_family_id$nl80211(&(0x7f00000000c0), 0xffffffffffffffff)
select(0x0, 0x0, &(0x7f0000000040), &(0x7f0000000080), &(0x7f00000000c0)={0x0, 0x2})
pipe(&(0x7f0000000080)={<r1=>0xffffffffffffffff})
splice(r1, 0x0, 0xffffffffffffffff, 0x0, 0xfffd, 0x0)
ioctl$sock_SIOCGIFINDEX_80211(0xffffffffffffffff, 0x8933, 0x0)
syz_open_dev$rtc(0x0, 0x0, 0x0)
r2 = openat$cgroup_ro(0xffffffffffffff9c, 0x0, 0x275a, 0x0)
r3 = socket(0x10, 0x2, 0x0)
getsockopt$sock_cred(r3, 0x1, 0x11, &(0x7f0000caaffb)={0x0, <r4=>0x0}, &(0x7f0000cab000)=0xc)
fchown(r2, r4, 0x0)
setreuid(0x0, 0x0)
fchown(r2, 0x0, 0x0)
connect$inet(0xffffffffffffffff, 0x0, 0x0)
r5 = openat$procfs(0xffffffffffffff9c, &(0x7f00000004c0)='/proc/sysvipc/msg\x00', 0x0, 0x0)
lseek(r5, 0x9, 0x0)

[  627.961589][ T9171] XFS (loop1): Unmounting Filesystem bfdc47fc-10d8-4eed-a562-11a831b3f791
executing program 2:
bpf$PROG_LOAD(0x5, &(0x7f00002a0fb8)={0x0, 0x4, &(0x7f00000004c0)=ANY=[@ANYBLOB="8500000007000000350000000000000085000000a000000095000000000000001b90b31a08f54ff40571eda5c56ad924a10c7b1e6003c9325fea577f8e56fe212b358f1d0838c8119ed74e74552ce4e2c8093375e35c8250f448a6a31260c2f9fbb70400000000000000b08b7aab5fd5d24dcff1ca14025b73c2da8f550900000000000000c340b111fcee90d6d90100000001000000babdee5b76635ce4f35f985e434196b5699ba66b9cb05e5259a1f61cafa3586a2228c4581dc2"], 0x0}, 0x90)
r0 = socket$nl_generic(0x10, 0x3, 0x10)
r1 = syz_genetlink_get_family_id$nl80211(&(0x7f0000000640), 0xffffffffffffffff)
r2 = socket$nl_netfilter(0x10, 0x3, 0xc)
getsockopt$inet_sctp6_SCTP_GET_PEER_ADDRS(0xffffffffffffffff, 0x84, 0x6c, &(0x7f00000005c0)={0x0, 0x78, "f3dcd9c3b134ea5dc4c0d086b0739a6d06f184e5fb193a8e68e02074c8e2f3a5f07d66c89afc9d57170f51ee968e63fa0bb85d3dfb0c13ebeda4908b55f15550cffdee42aa94d7992cddca9da43375c0482f5ae89db1a0a70afd7a913ad17e55637d145e3af9056ab902f54daff812a0c9f3b0a38a2e7e2d"}, 0x0)
ioctl$sock_SIOCGIFINDEX_80211(r2, 0x8933, &(0x7f0000000340)={'wlan1\x00', <r3=>0x0})
bpf$PROG_LOAD(0x5, &(0x7f0000000040)={0x0, 0x4, &(0x7f0000000680)=ANY=[@ANYBLOB="180200000400000000000000000000008500f5003600000095000000000000000a8cd378b09e7ffa318d9cc23d42836e0abe28a8e781a2c6ec1edbcce3f930bbd728eb5fddb992b077efbd59ef8b231db9d195af709ec038c0db020924fcc070636479703cdf8f58bb2abf7c"], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
sendmsg$NL80211_CMD_FRAME(r0, &(0x7f0000000440)={0x0, 0x0, &(0x7f0000000400)={&(0x7f0000000480)=ANY=[@ANYBLOB="98030000", @ANYRES16=r1, @ANYBLOB="010028057000fcdbdf253b00000008000300", @ANYRES32=r3, @ANYBLOB="04008e00080057001b0a000004006c000500190107000000080026006c0900005603330080b0c000ffffffffffff0802110000010569ea7fa08e8df3d0edd086922799ded6be01d09a95b66d3d90"], 0x398}}, 0x0)

[  628.237059][  T957] bond0 (unregistering): (slave bond_slave_0): Releasing backup interface
[  628.331848][  T957] bond0 (unregistering): (slave bond_slave_1): Releasing backup interface
[  628.363555][  T957] bond0 (unregistering): Released all slaves
executing program 2:
syz_mount_image$ext4(&(0x7f0000000140)='ext4\x00', &(0x7f00000005c0)='./file1\x00', 0x1018e58, &(0x7f0000000000), 0x1, 0x60f, &(0x7f0000000c40)="$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")
r0 = syz_usb_connect(0x0, 0x36, &(0x7f0000000200)=ANY=[@ANYBLOB="1201000014da2108ab12a390eb1e000000010902240001b30000040904410017ff5d810009050f1f01040000000905830300b3"], 0x0)
syz_usb_ep_write$ath9k_ep2(r0, 0x83, 0x8, &(0x7f0000000240)=ANY=[])

[  628.535830][T16179] loop2: detected capacity change from 0 to 1024
[  628.547015][  T957] IPVS: stopping backup sync thread 16128 ...
executing program 1:
r0 = syz_open_dev$evdev(&(0x7f00000000c0), 0x3f, 0x822f01)
sendmsg$IPCTNL_MSG_CT_NEW(0xffffffffffffffff, &(0x7f0000000040)={0x0, 0x0, &(0x7f0000000000)={&(0x7f00000001c0)={0x18, 0x0, 0x1, 0x0, 0x0, 0x0, {0x2}, [@CTA_TUPLE_ORIG={0x4}]}, 0x18}}, 0x0)
r1 = openat$mice(0xffffffffffffff9c, &(0x7f0000000180), 0x0)
write$char_usb(r0, &(0x7f0000000040)="e2", 0x918)
unshare(0x60480)
poll(&(0x7f0000000200)=[{r1}], 0x1, 0x0)

[  628.583208][T16179] EXT4-fs (loop2): stripe (65535) is not aligned with cluster size (4096), stripe is disabled
[  628.642188][T16179] EXT4-fs (loop2): revision level too high, forcing read-only mode
[  628.653941][T16179] EXT4-fs (loop2): orphan cleanup on readonly fs
executing program 1:
r0 = socket$nl_route(0x10, 0x3, 0x0)
r1 = socket$nl_generic(0x10, 0x3, 0x10)
sendmsg$netlink(r0, &(0x7f0000000040)={0x0, 0x0, &(0x7f0000000080)=[{&(0x7f0000000100)={0x2c, 0x13, 0x821, 0x0, 0x0, "", [@typed={0x8, 0x0, 0x0, 0x0, @fd=r1}, @typed={0x6, 0x0, 0x0, 0x0, @str='!\xa5'}, @nested={0xc, 0x3a, 0x0, 0x1, [@typed={0x5, 0x4c, 0x0, 0x0, @str='\x00'}]}]}, 0x2c}], 0x1}, 0x0)

executing program 4:
r0 = bpf$MAP_CREATE(0x0, &(0x7f00000000c0)=@base={0x1b, 0x0, 0x0, 0x8000}, 0x48)
r1 = bpf$PROG_LOAD(0x5, &(0x7f0000000340)={0xb, 0x1b, &(0x7f0000000140)=@ringbuf={{}, {{0x18, 0x1, 0x1, 0x0, r0}}, {}, [@ringbuf_query={{0x18, 0x1, 0x1, 0x0, r0}, {0x7, 0x0, 0xb, 0x2, 0x0, 0x0, 0x2}}, @printk={@lx}], {{}, {}, {0x85, 0x0, 0x0, 0x84}}}, &(0x7f0000000080)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_PROG_TEST_RUN(0xa, &(0x7f0000000240)={r1, 0xfca804a0, 0x10, 0x38, &(0x7f00000002c0)="b800000500000000", &(0x7f0000000300)=""/8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x4c)

[  628.770056][T16179] Quota error (device loop2): do_check_range: Getting dqdh_entries 512 out of range 0-14
[  628.776638][T16187] netlink: 'syz-executor.1': attribute type 58 has an invalid length.
executing program 1:
socket$inet6_tcp(0xa, 0x1, 0x0)
r0 = openat$rtc(0xffffff9c, &(0x7f0000000040), 0x0, 0x0)
ioctl$BTRFS_IOC_TREE_SEARCH(r0, 0x7005, 0x0)
r1 = syz_io_uring_setup(0x2ddd, &(0x7f00000006c0)={0x0, 0x0, 0x10100}, &(0x7f00000003c0), &(0x7f0000000440)=<r2=>0x0)
syz_io_uring_setup(0x5c4, &(0x7f0000000200), &(0x7f0000000140)=<r3=>0x0, &(0x7f00000002c0))
syz_io_uring_submit(r3, r2, &(0x7f00000001c0)=@IORING_OP_POLL_ADD={0x6, 0x0, 0x0, @fd_index=0x4})
io_uring_enter(r1, 0xa3d, 0x0, 0x0, 0x0, 0x0)
ioctl$FS_IOC_RESVSP(r4, 0x40305828, &(0x7f0000000080)={0x0, 0x0, 0x0, 0x8010002})

[  628.850304][T16179] Quota error (device loop2): qtree_write_dquot: Error -117 occurred while creating quota
[  628.886883][T16179] EXT4-fs error (device loop2): ext4_acquire_dquot:6886: comm syz-executor.2: Failed to acquire dquot type 0
[  628.955554][T16179] Quota error (device loop2): do_check_range: Getting dqdh_entries 512 out of range 0-14
executing program 4:
socket$inet6_tcp(0xa, 0x1, 0x0)
r0 = openat$rtc(0xffffff9c, &(0x7f0000000040), 0x0, 0x0)
ioctl$BTRFS_IOC_TREE_SEARCH(r0, 0x7005, 0x0)
r1 = syz_io_uring_setup(0x2ddd, &(0x7f00000006c0)={0x0, 0x0, 0x10100}, &(0x7f00000003c0), &(0x7f0000000440)=<r2=>0x0)
syz_io_uring_setup(0x5c4, &(0x7f0000000200), &(0x7f0000000140)=<r3=>0x0, &(0x7f00000002c0))
syz_io_uring_submit(r3, r2, &(0x7f00000001c0)=@IORING_OP_POLL_ADD={0x6, 0x0, 0x0, @fd_index=0x4})
io_uring_enter(r1, 0xa3d, 0x0, 0x0, 0x0, 0x0)
ioctl$FS_IOC_RESVSP(r4, 0x40305828, &(0x7f0000000080)={0x0, 0x0, 0x0, 0x8010002})

executing program 1:
r0 = socket$inet6_tcp(0xa, 0x1, 0x0)
listen(r0, 0x0)
ioctl$BTRFS_IOC_GET_DEV_STATS(r0, 0xc4089434, &(0x7f00000005c0)={0x0, 0x100000001, 0x0, [0x4, 0x8, 0x1, 0x1, 0x8000], [0xb76, 0x64, 0x39af, 0x0, 0x9861, 0x4, 0x8, 0x0, 0x9, 0x100000001, 0x401, 0x0, 0x3, 0x7fffffff, 0x8, 0x5, 0x2, 0x0, 0xccf, 0x1, 0x2, 0x6, 0x8, 0x6, 0x0, 0x1, 0x0, 0x0, 0xffffffffffffffff, 0x7d35, 0x0, 0xfffffffffffffff9, 0x3, 0x10001, 0x5, 0x10001, 0x0, 0x1, 0x7d, 0xfffffffffffffffc, 0x10001, 0x9, 0x7, 0x0, 0x80, 0x6, 0x0, 0x200, 0x2, 0x4, 0x0, 0x7ff, 0x1, 0x2, 0x8000000000000001, 0x4000000000, 0xffffffff, 0x7, 0x5, 0x9, 0x9, 0x24468503, 0x7, 0x4, 0x8, 0xfdf3, 0x4, 0x5, 0x3f, 0x4, 0x8000000000000000, 0x0, 0x8, 0xd6, 0x7, 0x7, 0xfffffffffffff8b8, 0x8000, 0x1, 0x88d4, 0x2, 0xfffffffffffffffa, 0xfffffffffffffdaa, 0x80, 0x1, 0x401, 0x0, 0x9f, 0x5, 0x7f, 0x9, 0x3e59, 0x1ff, 0x3, 0x7, 0x7, 0xffffffffffffffff, 0x4, 0x0, 0x7, 0x8000000000000000, 0xfffffffffffffffa, 0x7fff, 0x0, 0xb, 0x1, 0x5, 0x0, 0xd3, 0x0, 0x1, 0x0, 0x4, 0x8, 0x7fffffffffffffff, 0x7, 0x6, 0x4, 0xb44, 0x4, 0xad50]})
syz_open_dev$usbfs(&(0x7f0000000040), 0x12, 0x80801)
r1 = openat$sw_sync(0xffffffffffffff9c, &(0x7f0000000680), 0x0, 0x0)
ioctl$SW_SYNC_IOC_CREATE_FENCE(r1, 0xc0285700, &(0x7f0000000000)={0x5, "e0ffff13000000000000000000000000000000100000000000002000", <r2=>0xffffffffffffffff})
ioctl$SW_SYNC_IOC_CREATE_FENCE(r1, 0xc0285700, 0x0)
ppoll(&(0x7f0000000100)=[{r2}], 0x1, &(0x7f0000000140), 0x0, 0x0)
close(r1)

[  629.005515][T16179] Quota error (device loop2): qtree_write_dquot: Error -117 occurred while creating quota
[  629.054965][T16179] EXT4-fs error (device loop2): ext4_acquire_dquot:6886: comm syz-executor.2: Failed to acquire dquot type 0
[  629.069914][T16179] EXT4-fs error (device loop2): ext4_free_blocks:6576: comm syz-executor.2: Freeing blocks not in datazone - block = 0, count = 4096
[  629.102420][T16179] Quota error (device loop2): do_check_range: Getting dqdh_entries 512 out of range 0-14
[  629.124763][T16179] Quota error (device loop2): qtree_write_dquot: Error -117 occurred while creating quota
executing program 1:
syz_mount_image$vfat(&(0x7f0000000000), &(0x7f0000000100)='./file0\x00', 0x0, 0x0, 0x8, 0x0, &(0x7f0000000180))
mount$tmpfs(0x0, &(0x7f0000000080)='./file0\x00', &(0x7f0000000400), 0x0, 0x0)
chdir(&(0x7f0000000140)='./file0\x00')
r0 = openat$cgroup_ro(0xffffffffffffff9c, &(0x7f00000001c0)='pids.current\x00', 0x275a, 0x0)
mmap(&(0x7f0000000000/0xb36000)=nil, 0xb36000, 0x2, 0x12, r0, 0x0)
ftruncate(r0, 0xc17a)
setsockopt$netlink_NETLINK_TX_RING(0xffffffffffffffff, 0x10e, 0xc, &(0x7f0000000040), 0x213)
madvise(&(0x7f0000000000/0x600000)=nil, 0x600003, 0x19)

[  629.150949][T16179] EXT4-fs error (device loop2): ext4_acquire_dquot:6886: comm syz-executor.2: Failed to acquire dquot type 0
executing program 4:
r0 = openat(0xffffffffffffff9c, &(0x7f0000000040)='.\x00', 0x0, 0x0)
getdents64(r0, &(0x7f00000000c0)=""/154, 0x9a)
r1 = socket$inet_udp(0x2, 0x2, 0x0)
recvmmsg(r1, &(0x7f0000000080)=[{{0x0, 0x0, 0x0}}], 0x40000000000012d, 0x2, 0x0)
setsockopt$inet_int(r1, 0x0, 0x7, &(0x7f0000000180)=0x6, 0x4)
setsockopt$inet_int(r1, 0x0, 0x12, &(0x7f0000000140)=0x30, 0x4)
bind$inet(r1, &(0x7f0000000040)={0x2, 0x4e20, @empty}, 0x10)
setsockopt$EBT_SO_SET_ENTRIES(0xffffffffffffffff, 0xa00000000000000, 0x80, &(0x7f00000000c0)=@broute={'broute\x00', 0x20, 0x1, 0x0, [], 0x0, 0x0, 0x0}, 0xa08)
syz_emit_ethernet(0x36, &(0x7f0000000300)={@local, @link_local, @void, {@ipv4={0x800, @udp={{0x6, 0x4, 0x0, 0x0, 0x28, 0x0, 0x0, 0x0, 0x11, 0x0, @empty, @empty, {[@timestamp={0x44, 0x4, 0xc6}]}}, {0x0, 0x4e20, 0x10, 0x0, @gue={{0x2}}}}}}}, 0x0)

[  629.251630][T16179] EXT4-fs (loop2): 1 orphan inode deleted
[  629.277311][T16179] EXT4-fs (loop2): mounted filesystem 00000000-0000-0000-0000-000000000000 ro without journal. Quota mode: writeback.
[  629.294909][  T957] hsr_slave_0: left promiscuous mode
[  629.309413][  T957] hsr_slave_1: left promiscuous mode
executing program 1:
r0 = openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000040)='cpuacct.usage_sys\x00', 0x275a, 0x0)
write$binfmt_script(r0, &(0x7f0000020240), 0x10010)
mmap(&(0x7f0000000000/0x400000)=nil, 0x400000, 0x7, 0x10012, r0, 0x0)
r1 = socket$rds(0x15, 0x5, 0x0)
bind$rds(r1, &(0x7f0000000840)={0x2, 0x0, @loopback}, 0x10)
sendmsg$rds(r1, &(0x7f0000000000)={&(0x7f0000000040)={0x2, 0x0, @private=0xa010100}, 0x10, 0x0, 0x0, &(0x7f0000000780)=[@rdma_args={0x48, 0x114, 0x1, {{}, {0x0}, &(0x7f0000000080)=[{&(0x7f0000002640)=""/102389, 0x18ff5}], 0x1}}], 0x48}, 0x0)

[  629.348138][  T957] batman_adv: batadv0: Interface deactivated: batadv_slave_0
[  629.363005][  T957] batman_adv: batadv0: Removing interface: batadv_slave_0
executing program 4:
r0 = bpf$MAP_CREATE(0x0, &(0x7f00000009c0)=@base={0x5, 0x6, 0x8, 0x5}, 0x48)
r1 = bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x11, 0xd, &(0x7f0000000d40)=ANY=[@ANYBLOB="1800000000000000000000000000000018110000", @ANYRES32=r0, @ANYBLOB="0000000000000000b7080000000000007b8af8ff00000000bfa200000000000007020000f8ffffffb703000008000000b7040000000000008500000001000000850000000700000095"], &(0x7f0000001c00)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f0000000600)={&(0x7f00000005c0)='sys_enter\x00', r1}, 0x10)
bpf$MAP_UPDATE_CONST_STR(0x2, &(0x7f0000000a40)={{r0}, &(0x7f00000008c0), &(0x7f0000000940)='%-010d \x00'}, 0x20)
ioctl$SIOCSIFHWADDR(0xffffffffffffffff, 0x8946, 0x0)

[  629.398360][  T957] batman_adv: batadv0: Interface deactivated: batadv_slave_1
[  629.419866][  T957] batman_adv: batadv0: Removing interface: batadv_slave_1
[  629.458283][  T957] veth1_macvtap: left promiscuous mode
[  629.480565][  T957] veth0_macvtap: left promiscuous mode
[  629.486505][  T957] veth1_vlan: left promiscuous mode
[  629.491942][  T957] veth0_vlan: left promiscuous mode
executing program 4:
mknodat(0xffffffffffffff9c, &(0x7f0000000040)='./file0\x00', 0x0, 0x0)
mknodat(0xffffffffffffff9c, &(0x7f0000000180)='./file5\x00', 0x61c0, 0x700)
r0 = landlock_create_ruleset(&(0x7f0000000240)={0x1fff}, 0x10, 0x0)
landlock_restrict_self(r0, 0x0)
renameat2(0xffffffffffffff9c, &(0x7f0000000a00)='./file0\x00', 0xffffffffffffff9c, &(0x7f0000000a40)='./file5\x00', 0x2)

[  629.591477][   T57] usb 3-1: new high-speed USB device number 23 using dummy_hcd
[  629.637546][ T5093] Bluetooth: hci2: command tx timeout
executing program 4:
r0 = openat$dir(0xffffffffffffff9c, &(0x7f0000000040)='./file0\x00', 0x0, 0x0)
ioctl$BTRFS_IOC_BALANCE_V2(r0, 0xca289435, &(0x7f0000000400)={0x1, 0x0, {0x0, @struct, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, @struct}, {0x0, @usage, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, @struct}, {0x0, @struct, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, @struct}})

executing program 3:
socket$nl_generic(0x10, 0x3, 0x10)
r0 = socket$nl_generic(0x10, 0x3, 0x10)
sendmsg$nl_generic(r0, &(0x7f0000000100)={0x0, 0x0, &(0x7f0000000180)={&(0x7f00000001c0)={0x14, 0x21, 0x1, 0x0, 0x0, {0x2, 0x2}}, 0x14}}, 0x0)

[  629.875006][   T57] usb 3-1: Using ep0 maxpacket: 8
[  629.994970][   T57] usb 3-1: config 179 has an invalid interface number: 65 but max is 0
[  630.003288][   T57] usb 3-1: config 179 has no interface number 0
[  630.029649][   T57] usb 3-1: config 179 interface 65 altsetting 0 endpoint 0xF has an invalid bInterval 0, changing to 7
[  630.071148][   T57] usb 3-1: config 179 interface 65 altsetting 0 endpoint 0xF has invalid maxpacket 1025, setting to 1024
executing program 3:
bpf$MAP_CREATE(0x0, 0x0, 0x0)
r0 = bpf$PROG_LOAD(0x5, &(0x7f0000000440)={0x11, 0x6, &(0x7f0000000a40)=ANY=[@ANYBLOB="050000000000000061110c00000000008510000002000000850000000800000095000000000000009500a5050000000077d8f3b423cdac8d8000000000000020e16ad10a48b243ccc42606d25dfd73a015e0ca7fc2506a0f68a7d06d10bfe150a7487535f7866907dc6751dfb265a0e3ccae669e173a649c1cfd6587d452d46b7c57d77578f4c35235138d5521f9453559c3421eed73d5661cfeecf9c66c54c3b3ffe1b4ce25d7c983c044c03bf3ff03fe3e26e7a23129d6606fd28a7f9105f82317874b33d96b39fa4e045469989d552af6200000003a00000000000000abecc2f4a3799af2551ce935b0f327cb3f011a7d06602e2fd5234712596b696418f1623ed38ae89d24e14b40234756ddcebfba2f87925bfacba83109753f543ad027edd68149ee99eebc6f7d6dd4aed4afe1f44ccb19e810879b70a70900000000000000000000d7900a820b6327944e9a217b9800e02a92895614cd50cbf83a1ed25268816b004519c9c5cff097d8000000000009d27d753a30a147b24a48435bd8a568669596e9e08679b3ce48e90defb6670c3d6209000000c773713a66b223fa8b148871c8d31d24000025449f106b99893ed20fa7a050fbbef90327e827e513e9606800000000e89f9c85c822a961546ed5363c17ff1432d08806bc376e3e69ee52b59d13182e1f24ed208ada12f7a1525320e71666f472a972d5eb1affb87ba55b2d72078e9f40b4ae7dc3b2aeb0d11cd22c35d32940f19dff00ffffffff080000ff003853e59de7621e348955735264f34b1046a1813668297a7edad187ef106ae7fcbb25090f17d0baadeb8ae190a1fb5a315f8347fb0379659500000000000000000000000000000000000000002fdf0193ec79c90ed210ebc2fbed6d4216770c1b0dec886b388d138c2b69c6aacb714e7264093061c660a5100b7cc165889eb94c8d7c77b6fa06f1a4f8e4a6b6cb37e319c5c22f276b03cae853f42b07ca0b03b1eb32a6b1a81cd511fd0b59d57a11c6a3ebf9731464ad21f07f618efc31023ac60007426162b57e803519954d7c956fda392fa84be38e937d36af1c35138e05a9e8d6dc0272de72c41500000000304402e22af23437126f330f8eb4075daaeae3134ece35cd86d95bd9836bd186c4b6565e967a4e3e86f299b7400994ba136b4eccf3b0f001a266c0d160b3ce1182001d64b52a5ce7f506295d59eea6903b84ffbabf5a5b91c1d6ecce8728a224aec66c610e3becd60a35e848c224f8251947eed20e2b612cb099bfe8924d33ba7f0691fed04a43e9c64b7a1e3165e86cdb9871c678a6bbb14821f441c6c14d1bd78d8ffdfea12c19ea04264335d60b6b7a7da6fb83f33101db32f6ab137d943dd3c1e8db9f3e1263573dc721ae82fe0bc63598751a5092c9f7dbfc39d564834e3703492c2a651643d8ce5c36d97a4812cf73fc8ea0d68d7489cfcb0176"], &(0x7f0000000080)='GPL\x00', 0x5, 0x29e, &(0x7f000000cf3d)=""/195, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x6}, 0x70)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f0000000040)={&(0x7f0000000000)='kmem_cache_free\x00', r0}, 0xb)
bpf$PROG_LOAD(0x5, 0x0, 0x0)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, 0x0, 0x0)
listen(0xffffffffffffffff, 0x0)
io_setup(0x0, 0x0)
r1 = socket$key(0xf, 0x3, 0x2)
prctl$PR_SET_TAGGED_ADDR_CTRL(0x37, 0x0)
syz_open_dev$usbfs(0x0, 0x0, 0x0)
sendmsg$key(r1, &(0x7f0000000080)={0x0, 0x0, &(0x7f0000000040)={&(0x7f00000000c0)={0x2, 0xe, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, [@sadb_address={0x2, 0x7, 0x0, 0x0, 0x0, @in={0x2, 0x0, @initdev={0xac, 0x1e, 0x0, 0x0}}}]}, 0x28}}, 0x0)

[  630.111912][   T57] usb 3-1: config 179 interface 65 altsetting 0 endpoint 0x83 has an invalid bInterval 0, changing to 7
[  630.139834][   T57] usb 3-1: config 179 interface 65 altsetting 0 endpoint 0x83 has invalid maxpacket 41728, setting to 1024
[  630.172326][   T57] usb 3-1: config 179 interface 65 altsetting 0 has 2 endpoint descriptors, different from the interface descriptor's value: 23
[  630.211480][   T57] usb 3-1: New USB device found, idVendor=12ab, idProduct=90a3, bcdDevice=1e.eb
[  630.232218][   T57] usb 3-1: New USB device strings: Mfr=0, Product=0, SerialNumber=0
[  630.275571][T16179] raw-gadget.0 gadget.2: fail, usb_ep_enable returned -22
executing program 3:
syz_mount_image$fuse(0x0, &(0x7f0000000080)='./file0\x00', 0x0, 0x0, 0x0, 0x0, 0x0)
mount(0x0, &(0x7f0000000000)='./file0\x00', &(0x7f00000000c0)='mqueue\x00', 0x0, 0x0)
chdir(&(0x7f0000000380)='./file0\x00')
ioperm(0x0, 0x4, 0x7)
msgctl$IPC_SET(0x0, 0x2, 0x0)
add_key$fscrypt_v1(0x0, &(0x7f0000000180)={'fscrypt:', @desc1}, &(0x7f00000001c0)={0x0, "cb96a945ab526fe377145584b62491050e011fd59d1396798a98902d3fafc9e09a29e6671ad9f5f25693b12e5d0ac30e15fd59e58f7200"}, 0x48, 0xfffffffffffffffe)
pipe2$watch_queue(&(0x7f0000000280), 0x80)
mount$9p_fd(0x0, 0x0, 0x0, 0x0, &(0x7f0000000940)={'trans=fd,', {}, 0x2c, {}, 0x2c, {[{@msize}, {@nodevmap}, {@version_L}, {@nodevmap}, {@access_user}, {@privport}, {@cache_mmap}, {@privport}], [{@seclabel}, {@smackfstransmute={'smackfstransmute', 0x3d, '[\x8a'}}]}})
openat(0xffffffffffffff9c, &(0x7f0000000040)='.\x00', 0x0, 0x0)
openat(0xffffffffffffff9c, &(0x7f0000004280)='./file0\x00', 0x0, 0x0)
r0 = openat$cgroup_ro(0xffffffffffffffff, 0x0, 0x275a, 0x0)
ioctl$EXT4_IOC_SETFSUUID(r0, 0x4008662c, 0x0)
bpf$PROG_LOAD(0x5, 0x0, 0x0)
openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000280)='cgroup.controllers\x00', 0x275a, 0x0)

[  630.407197][  T957] team0 (unregistering): Port device team_slave_1 removed
[  630.416731][T16203] loop1: detected capacity change from 0 to 32768
[  630.475475][T16203] XFS (loop1): Mounting V5 Filesystem bfdc47fc-10d8-4eed-a562-11a831b3f791
[  630.477065][  T957] team0 (unregistering): Port device team_slave_0 removed
[  630.600222][T16203] XFS (loop1): Ending clean mount
[  630.616874][T16223] kernel read not supported for file /cgroup.controllers (pid: 16223 comm: syz-executor.3)
[  630.648115][   T29] audit: type=1800 audit(1715377310.174:983): pid=16223 uid=0 auid=4294967295 ses=4294967295 subj=_ op=collect_data cause=failed comm="syz-executor.3" name="cgroup.controllers" dev="mqueue" ino=60722 res=0 errno=0
executing program 1:
r0 = bpf$MAP_CREATE(0x0, &(0x7f00000000c0)=@base={0x1b, 0x0, 0x0, 0x8000}, 0x48)
r1 = bpf$PROG_LOAD(0x5, &(0x7f0000000340)={0xb, 0x1b, &(0x7f0000000140)=@ringbuf={{}, {{0x18, 0x1, 0x1, 0x0, r0}}, {}, [@ringbuf_query={{0x18, 0x1, 0x1, 0x0, r0}, {0x7, 0x0, 0xb, 0x2, 0x0, 0x0, 0x2}}, @printk={@lx}], {{}, {}, {0x85, 0x0, 0x0, 0x84}}}, &(0x7f0000000080)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_PROG_TEST_RUN(0xa, &(0x7f0000000240)={r1, 0xfca804a0, 0x10, 0x38, &(0x7f00000002c0)="b800000500000000", &(0x7f0000000300)=""/8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x4c)

[  630.718812][   T57] usb 3-1: USB disconnect, device number 23
[  630.745114][    C1] xpad 3-1:179.65: xpad_irq_in - usb_submit_urb failed with result -19
[  630.753486][    C1] xpad 3-1:179.65: xpad_irq_out - usb_submit_urb failed with result -19
executing program 3:
r0 = socket$inet6_tcp(0xa, 0x1, 0x0)
listen(r0, 0x0)
ioctl$BTRFS_IOC_GET_DEV_STATS(r0, 0xc4089434, &(0x7f00000005c0)={0x0, 0x100000001, 0x0, [0x4, 0x8, 0x1, 0x1, 0x8000], [0xb76, 0x64, 0x39af, 0x0, 0x9861, 0x4, 0x8, 0x0, 0x9, 0x100000001, 0x401, 0x0, 0x3, 0x7fffffff, 0x8, 0x5, 0x2, 0x0, 0xccf, 0x1, 0x2, 0x6, 0x8, 0x6, 0x0, 0x1, 0x0, 0x0, 0xffffffffffffffff, 0x7d35, 0x0, 0xfffffffffffffff9, 0x3, 0x10001, 0x5, 0x10001, 0x0, 0x1, 0x7d, 0xfffffffffffffffc, 0x10001, 0x9, 0x7, 0x0, 0x80, 0x6, 0x0, 0x200, 0x2, 0x4, 0x0, 0x7ff, 0x1, 0x2, 0x8000000000000001, 0x4000000000, 0xffffffff, 0x7, 0x5, 0x9, 0x9, 0x24468503, 0x7, 0x4, 0x8, 0xfdf3, 0x4, 0x5, 0x3f, 0x4, 0x8000000000000000, 0x0, 0x8, 0xd6, 0x7, 0x7, 0xfffffffffffff8b8, 0x8000, 0x1, 0x88d4, 0x2, 0xfffffffffffffffa, 0xfffffffffffffdaa, 0x80, 0x1, 0x401, 0x0, 0x9f, 0x5, 0x7f, 0x9, 0x3e59, 0x1ff, 0x3, 0x7, 0x7, 0xffffffffffffffff, 0x4, 0x0, 0x7, 0x8000000000000000, 0xfffffffffffffffa, 0x7fff, 0x0, 0xb, 0x1, 0x5, 0x0, 0xd3, 0x0, 0x1, 0x0, 0x4, 0x8, 0x7fffffffffffffff, 0x7, 0x6, 0x4, 0xb44, 0x4, 0xad50]})
syz_open_dev$usbfs(&(0x7f0000000040), 0x12, 0x80801)
r1 = openat$sw_sync(0xffffffffffffff9c, &(0x7f0000000680), 0x0, 0x0)
ioctl$SW_SYNC_IOC_CREATE_FENCE(r1, 0xc0285700, &(0x7f0000000000)={0x5, "e0ffff13000000000000000000000000000000100000000000002000", <r2=>0xffffffffffffffff})
ioctl$SW_SYNC_IOC_CREATE_FENCE(r1, 0xc0285700, 0x0)
ppoll(&(0x7f0000000100)=[{r2}], 0x1, &(0x7f0000000140), 0x0, 0x0)
close(r1)

[  630.818767][ T9171] XFS (loop1): Unmounting Filesystem bfdc47fc-10d8-4eed-a562-11a831b3f791
[  630.971235][T16209] loop4: detected capacity change from 0 to 32768
[  631.001971][T16170] chnl_net:caif_netlink_parms(): no params data found
executing program 3:
bpf$MAP_CREATE(0x0, &(0x7f00000000c0)=@base={0x1b, 0x0, 0x0, 0x8000}, 0x48)
r0 = bpf$MAP_CREATE(0x0, &(0x7f00000000c0)=@base={0x1b, 0x0, 0x0, 0x8000}, 0x48)
r1 = bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x11, 0x7, &(0x7f0000000240)=@framed={{}, [@ringbuf_query={{0x18, 0x1, 0x1, 0x0, r0}}]}, &(0x7f0000000040)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f0000000180)={&(0x7f0000000140)='kmem_cache_free\x00', r1}, 0x10)
mkdirat(0xffffffffffffff9c, &(0x7f0000002040)='./file0\x00', 0x0)
pipe2$9p(&(0x7f0000000240), 0x0)
bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x0, 0xc, &(0x7f0000000440)=ANY=[@ANYRESDEC, @ANYRES32, @ANYBLOB="0000000000000000b7080000000000007b8af8ff00000000bfa200000000000007020000f8ffffffb703000008000000b704000000000000850000000100000095"], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
r2 = bpf$MAP_CREATE(0x0, &(0x7f0000000180)=@base={0xb, 0x5, 0x400, 0x9, 0x1}, 0x48)
bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x0, 0xc, &(0x7f0000000440)=ANY=[@ANYBLOB="1800000000000000000000000000000018110000", @ANYRES32, @ANYBLOB="0000000000000000b708000008"], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$PROG_LOAD(0x5, &(0x7f0000000340)={0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x1b, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$MAP_GET_NEXT_KEY(0x2, &(0x7f00000004c0)={r2, &(0x7f0000000340), &(0x7f00000005c0)=""/155}, 0x20)
bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x0, 0x0, &(0x7f0000000440)=ANY=[@ANYBLOB="1800000000800000000000000000000018110000", @ANYRES32=r2], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
fsetxattr$security_capability(0xffffffffffffffff, &(0x7f0000000000), 0x0, 0x0, 0x0)
r3 = socket$vsock_stream(0x28, 0x1, 0x0)
fgetxattr(r3, &(0x7f0000000000)=ANY=[], 0x0, 0x0)

[  631.010625][T16209] BTRFS: device fsid c9fe44da-de57-406a-8241-57ec7d4412cf devid 1 transid 8 /dev/loop4 (7:4) scanned by syz-executor.4 (16209)
[  631.038196][T16209] BTRFS info (device loop4): first mount of filesystem c9fe44da-de57-406a-8241-57ec7d4412cf
[  631.069525][T16209] BTRFS info (device loop4): using crc32c (crc32c-intel) checksum algorithm
[  631.089244][T16209] BTRFS info (device loop4): using free-space-tree
executing program 3:
r0 = openat$tun(0xffffffffffffff9c, &(0x7f0000000140), 0x0, 0x0)
ioctl$TUNSETIFF(r0, 0x400454ca, &(0x7f0000000080)={'pimreg0\x00', 0x7c2})
ioctl$TUNATTACHFILTER(r0, 0x401054d5, &(0x7f0000000040)={0x5, &(0x7f0000000100)=[{0x35, 0x0, 0x3}, {}, {}, {}, {0x6}]})

executing program 2:
socket(0x10, 0x803, 0x0)
r0 = socket$netlink(0x10, 0x3, 0x0)
socketpair$unix(0x1, 0x5, 0x0, &(0x7f00000000c0)={0xffffffffffffffff, <r1=>0xffffffffffffffff})
r2 = dup(r1)
getsockname$packet(r2, &(0x7f00000000c0)={0x11, 0x0, <r3=>0x0, 0x1, 0x0, 0x6, @random}, &(0x7f0000000140)=0x14)
sendmsg$nl_route(r0, &(0x7f0000000080)={0x0, 0x0, &(0x7f0000000040)={&(0x7f0000000500)=@newlink={0xec, 0x10, 0x801, 0x0, 0x0, {0x0, 0x0, 0x0, r3}, [@IFLA_AF_SPEC={0xcc, 0x1a, 0x0, 0x1, [@AF_INET6={0x18, 0x2, 0x0, 0x1, [@IFLA_INET6_TOKEN={0x14, 0x7, @local}]}, @AF_INET={0x30, 0x2, 0x0, 0x1, {0x4, 0x1, 0x0, 0x1, [{0x3}, {0x8}, {0x4}, {0x8}, {0x8}]}}, @AF_INET={0x18, 0x2, 0x0, 0x1, {0x14, 0x1, 0x0, 0x1, [{0x11}, {0x8}]}}, @AF_INET6={0x18, 0xa, 0x0, 0x1, [@IFLA_INET6_TOKEN={0x14, 0x7, @mcast2}, @IFLA_INET6_TOKEN={0x0, 0x7, @mcast2}, @IFLA_INET6_TOKEN={0x0, 0x7, @dev}]}, @AF_INET={0x28, 0x2, 0x0, 0x1, {0x24, 0x1, 0x0, 0x1, [{0x8}, {0x8}, {0x8}, {0x8}]}}, @AF_MPLS={0x4}, @AF_INET6={0x0, 0xa, 0x0, 0x1, [@IFLA_INET6_TOKEN={0x0, 0x7, @rand_addr=' \x01\x00'}, @IFLA_INET6_ADDR_GEN_MODE, @IFLA_INET6_ADDR_GEN_MODE, @IFLA_INET6_TOKEN={0x0, 0x7, @dev}, @IFLA_INET6_TOKEN={0x0, 0x7, @mcast2}, @IFLA_INET6_TOKEN={0x0, 0x7, @rand_addr=' \x01\x00'}, @IFLA_INET6_TOKEN={0x0, 0x7, @private1}, @IFLA_INET6_ADDR_GEN_MODE, @IFLA_INET6_ADDR_GEN_MODE]}, @AF_MPLS={0x4}]}]}, 0xec}}, 0x0)

[  631.276730][T16170] bridge0: port 1(bridge_slave_0) entered blocking state
[  631.284201][T16170] bridge0: port 1(bridge_slave_0) entered disabled state
[  631.295871][T16170] bridge_slave_0: entered allmulticast mode
[  631.303614][T16170] bridge_slave_0: entered promiscuous mode
[  631.324974][T14884] EXT4-fs (loop2): unmounting filesystem 00000000-0000-0000-0000-000000000000.
[  631.347819][T16170] bridge0: port 2(bridge_slave_1) entered blocking state
[  631.356483][T16170] bridge0: port 2(bridge_slave_1) entered disabled state
[  631.363827][T16170] bridge_slave_1: entered allmulticast mode
[  631.383066][T16170] bridge_slave_1: entered promiscuous mode
executing program 4:
bpf$BPF_PROG_RAW_TRACEPOINT_LOAD(0x5, &(0x7f0000001c40)={0x0, 0x3, &(0x7f0000001300)=ANY=[@ANYBLOB="1800000001000000000000000000000095"], 0x0}, 0x90)
r0 = openat(0xffffffffffffff9c, &(0x7f0000000200)='./cgroup\x00', 0x0, 0x0)
r1 = bpf$BPF_PROG_RAW_TRACEPOINT_LOAD(0x5, &(0x7f0000000040)={0x8, 0x3, &(0x7f0000001300)=ANY=[], &(0x7f00000001c0)='syzkaller\x00'}, 0x90)
bpf$BPF_LINK_CREATE(0x1c, &(0x7f0000000780)={r1, r0, 0x16, 0x0, @void}, 0x10)
r2 = openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000040)='memory.events\x00', 0x275a, 0x0)
r3 = openat$cgroup_ro(0xffffffffffffff9c, &(0x7f00000000c0)='memory.events\x00', 0x275a, 0x0)
write$binfmt_script(r2, &(0x7f0000000100), 0xfecc)
mmap(&(0x7f0000000000/0x3000)=nil, 0x3000, 0x1, 0x12, r3, 0x0)
r4 = socket$inet6(0xa, 0x80001, 0x0)
setsockopt$inet6_group_source_req(r4, 0x29, 0x2e, &(0x7f0000000200)={0x0, {{0xa, 0x0, 0x0, @mcast1={0xff, 0x7}}}, {{0xa, 0x0, 0x0, @ipv4={'\x00', '\xff\xff', @local}}}}, 0x108)

[  631.465943][T15853] BTRFS info (device loop4): last unmount of filesystem c9fe44da-de57-406a-8241-57ec7d4412cf
[  631.645971][T16251] A link change request failed with some changes committed already. Interface ip_vti0 may have been left with an inconsistent configuration, please check.
[  631.714830][ T5093] Bluetooth: hci2: command tx timeout
executing program 2:
r0 = openat$udambuf(0xffffffffffffff9c, &(0x7f00000000c0), 0x2)
ftruncate(r1, 0xffff)
fcntl$addseals(r1, 0x409, 0x7)
r2 = ioctl$UDMABUF_CREATE(r0, 0x40187542, &(0x7f0000000000)={r1, 0x0, 0x0, 0x10000})
mmap(&(0x7f0000ffa000/0x2000)=nil, 0x2000, 0x0, 0x11, r2, 0xffffc000)
syz_open_dev$MSR(&(0x7f00000001c0), 0x0, 0x0)
openat$binder_debug(0xffffffffffffff9c, 0x0, 0x0, 0x0)
syz_mount_image$hfs(&(0x7f0000000140), &(0x7f0000000280)='./bus\x00', 0xc090, &(0x7f0000002700)=ANY=[], 0xff, 0x266, &(0x7f00000003c0)="$eJzs3c9qE10Yx/HfmeR9jbbU6R8RxFW14ErauhE3guQO3LgStYlQDBW0grqqrsULcO8teBGuxLXgzpUXkF3kPHNiJmkmE0PTk6TfDyQknfPMPCdzpuc8U0oE4My6V//5+dYv/3BSRRVJd6REUk2qSrqky7VXB4f7h61mY9SOKhbhH05ZpDvWZu+gOSzUx1lEkPp3VS3nf4bpqP2InQFmgV39QyTSuXB12vbaqWc2HUexE4jMtdXWa63EzgMAEFeY/5Mwzy+H9XuSSFth2u+f/+d8Am3HTiCy3PxvVVbH+fN70Tb16j0r4fz2pFslTnKs/5WNrL4FpiurKi2X5PzT/Vbz5t7zViPRe90Ncs027LmRDd2ufLbvju96c0htOsLkfV+yPvzn+7BbkP/6yR6xnPvqvrmHLtUnNf6u/6od50+Tnal04Exl+W8X79F6mWatCnq5age5Eo4QjOxlRQUVibojalX9NwjSsjwtam0gKuvdTknU+tCo3ZKojcGo3mgujpw299E9cJv6rS+q59b/if+0tzTOlenbWMswMkb2p2otU5tPwlV3dHVoy2TSHmECH/REt7Xy8s3bZ49breYLXpyhF91BMCv5LOwL/yFHOXp33pl8P9F+M+EU9U76Pwbyt5lF4dddLqv/cvXKti3W/FM6Yp3eKdt5bo87BbXBmj1fKK7g+ji79bBUXMGNW3NduyFdH+eImTTkuSBcXd/1iPv/AAAAAAAAAAAAAAAAAAAA8+bk/uWgpqJNsfsIAAAAAAAAAAAAAAAAAAAAAMC8m7nv/72v7B3f/wtM3Z8AAAD//9YVdvU=")
r3 = openat(0xffffffffffffff9c, &(0x7f0000000040)='.\x00', 0x0, 0x0)
capset(&(0x7f0000000300)={0x20071026}, &(0x7f0000000340))
r4 = openat$binder_debug(0xffffffffffffff9c, &(0x7f0000000040)='/sys/kernel/debug/binder/transactions\x00', 0x0, 0x0)
read$FUSE(r4, &(0x7f0000000480)={0x2020, 0x0, 0x0, 0x0, <r5=>0x0}, 0x2020)
fchown(r3, 0xffffffffffffffff, r5)
openat$fuse(0xffffffffffffff9c, 0x0, 0x42, 0x0)
llistxattr(0x0, 0x0, 0x0)
socket$nl_generic(0x10, 0x3, 0x10)
r6 = socket$netlink(0x10, 0x3, 0x0)
r7 = socket$inet_udplite(0x2, 0x2, 0x88)
ioctl$sock_SIOCGIFINDEX(r7, 0x8933, &(0x7f0000000340)={'bridge_slave_0\x00', <r8=>0x0})
sendmsg$nl_route(r6, &(0x7f00000003c0)={0x0, 0x0, &(0x7f0000000200)={&(0x7f0000000000)=ANY=[@ANYBLOB="3402fbe6f8460cc2cc0000000000000007000000", @ANYRES32=r8, @ANYBLOB="000000000000000014001a80100004800c00038044fd000000000000"], 0x34}}, 0x0)
r9 = syz_open_dev$tty1(0xc, 0x4, 0x1)
r10 = dup(r9)
write$UHID_INPUT(r10, &(0x7f0000000000)={0x12, {"a2e3ad21ed0d09f91b5b090987f70906d038e7ff7fc6e5539b0d3d0e8b089b323b6d07060890e0878f0e1ac6e7049b334a959b3e9a240d5b67f3988f7ef319520100ffe8d178708c523c921b1b5b31070b07580936cd3b78130daa61d8e8040000005802b77f07227227b7ba67e0e78657a6f5c2a874e62a9ccdc0d31a0c9f318c0da1993bd160e233df4a62179c6f30e065cd5bcd0ae193973735b36d5b1b63dd1c00305d3f46635eb016d5b1dda98e2d749be7bd1df1fb3b231fdcdb5075a9aaa1b469c3090000000000000075271b286329d169934288fd789aa37d6e98b224fd44b65b31334ffc55cc82cd3ac32ecdb08ced6f9081b4dd0d8b38f3cd4498bee800490841bdb114f6b76383701d8f5c55432a909fda039aec54a1236e80f6a8abadea7662496bddbb42be6bfb2f17959d1f416e56c71b1931870262f5e801119242ca026bfc821e7e7daf2451138e645bb80c617669314e2fbe70de98ec76a9e40dad47f36fd9f7d0d42a4b5f1185ccdcf16ff46295d8a0fa17713c5802630933a9a34af674f3f39fe23491237c08822dec110911e893d0a8c4f677747abc360934b82910ff85bfd995083bba2987a67399eac427d145d546a40b9f6ff14ac488ec130fb3850a27af9544ae15a7e454dea05918b41243513f000000000000000a3621c56cea8d20fa911a0c41db6ebe8cac64f17679141d54b34bbc9963ac4f4bb3309603f1d4ab966203861b5b15a841f2b575a8bd0d78248ebe4d9a80002695104f674c2431dca141fae269cab70e9a66f3c3a9a63e9639e1f59c0ede26c6b5d74b078a5e15771aaa18119a867e1088334975e9f73483b6a62fa678ca14ffd9f9db2a7869d85864056526f889af43a6056080572286522449df466c632b3570243f989cce7cd9f465e41e610c20d80421d653a5520000008213b704c7fb082ff27590678ef9f190bae97909507041d860420c5664b27921b14dc1db8892fd32d0ad7bad8deff4b05f60cea0da7710ac0000000000008000bea37ce0d0d4aa202f928f28381aab144a5d429a04a6a2b83c7068ae949ed06e288e810bac9c76600025e19c907f8ea2e2010000008271a1f5f8528f227e79c1389dbdfffe492f21579d2c15b8c70cdb1c332d86d87341432750861ec2bc3451edca194b221cfec4603d276bbaa1dfa6d4fb8a48a76eafc9a9a0270e4c10d64cd5a62427264f2377fe763c43470833ac96c45f357cbbaba8f1b1fdcc7cbb61a7cdb9744ed7f9129aede2be21ccfdc4e9134f8684b3a4f354da9a795e96334e207dff70f1988037b2ed3aaf575c0b88d8f146684078416d59fdee5325928974d12dad99dac44c3f0008047096a44002bebc2420aed92fa9b6578b4779415d4ac01b75d5495c118045651cf41c2fc48b778efa5ea5677747430af4162b987b80c3e001cd34e5c92f76cc4c24eeb8bc4e9ac2aed9e53803ed0ca4ae3a9737d214060005ea6f1783e287b3bee96e3a726eafe2fdfaa78d1f48c13b64df07847754b8400daaa69bf5c8f4350aeae9ca1207e78283cd0b20ceb360c7e658828163e2d25c4aa348561f927e88f63aa70e73a5e69b3df3495903f06572e1e007fa55a2999f596d067312f5779e8dbfdcf3427138f3d444d2639a10477f9bec4b0bbb6e3c04be68981f392203dd0ee3ef478e16dacfc5e3e03cf7ab8e3902f1b0ff034ef655b253ca509383815b1b6fc6522d4e4fdc11a48cf42d48604675fde2b94cf00500a2690891abf8ab9c015073014d9e08d4338b8780bdecd436cf0541359bafffa45237f104b96210403b2de9efed496f42355bc7872c827467cfa5c4e72730d56bd068ed211cf847535edecb7b373f78b095b68441a34cb51682a8ae4d24ad0465f3927f889b813076038e79a7962fb385a882e8020f06c4c2ba1dd5cac7c18876da865d258734dd73583df292892448039ef799cf0630becdcce04579b5561dc825ab829827945e020c1f67ee615feb6243378e0610060f02cca4e91b2f001edb3d78fb4b55668dda93aec92a5de203717aa49c2d284acfabe262fccfcbb2b75a2183c46eb65ca8104e1b4da7fbb77ab2fc043aead87c32ab875ee7c2e7b7019c982cd3b43eaeb1a5fb135c0c7dcee8fe6516a328032f88c042891824659e9e94265c803b35ee5f83a2b210520106b8a358b50ab7a1fa89af9c251fe5294b3d1802d5676d95f160ec97b1ad94872cb2044642c37b4a6cc6c04effc1672db7e4b6080000007a508ae54b3cd7369dde50e8c77d95a3d361c040babb171607caac2a3559ad4f75465f49c0d0ae3716db6e00cb11db4a5fade2a57c10238e204a67737c3b42aae501b20f7694a00f16e2d0174035a2c22656dc29880acebdbe8ddbd75c2f998d8ac2dfad2ba3a504767b6b45a45957f24d758ed024b3849c11d412a2a03b4047497022d9c30e23ef4df5c89644f48bb536f7945b59d7bcddff754413d135273ea8e75f22f216c6b9990ae71806f2c00b4025c48b75c0f73cdb9a7b8fa367b50028067e7f16f4dd569d462f4f19eacdb3ed70eeebb4483f8fd777d443e8b40427db6fe29068c0ca3d2414442e8f3a154704b0e51bc664a137b26be719f4f7c9a5678a674dfc95df80b9ce375dd649c8c704e509bd88c8e63d8c7dd67071115c8982ba46af4d6adcc9f68a75b9397b035153faf46366e7205dd8d6f37525c1a0e94610dd94323f6c15d085197149bfd6655548cfd9c52c9711937f79abb1a124f1210465483cd3b2d78378cfb85ed82e7da0f6eb6d279f2ae455925d0f6f1ba571eba281f2a654fb39dd0000000039ff158e7c5419e037f3e3ad038f2211f1033195563c7f93cd54b9094f226e783271e1e5a2a2c10712eab625d64931cd4ffe6738d97b9b5ef828ee9fb06ffc01af0e79c1e14b1d25988c69a399567c1d93768f7971d31488b8658a20878b7c1dd7ba02fc42939dde3d4a3339a65d507dc59c51097b40517705da56e9ebf0afa53282bf86dbb58c548069ff6eb95aade7cc66d7bbef724779ca1f731b3346ff177050373d79ff7b3e7f9bc0c1b4b266a8878b90baaa039d3e3b63979ac3df6e6f4859afd50238c7547a39b60810938044ae185d2ba3e00a4e73676864ae090d81eaee5ee6cf1d0ab378dd4dd891e937c2ea5410e0513005000000000000003911fab964c271550027697b52160687461602f88df165d884b36ec2b6c25a2f33c715687e9d4afb96d6861aca47da73d6f3144345f48843dd014e5c5ad8fe995754bd9cf32fce1e31919c4b2082fb0a30b9deae84bed4b28045634073c9c58c89d9e99c81769177c6d594f88a4facfd4c735a20307c737afa2d60399473296b831dbd933d93994ba3064279b10ea0c5833f41f157ea2302993dbe433b1aa3a3766d5439020484f4113c4c859465c3b415c3432f81db8719539d5bf372aaaea1cc43a6c5cbe59758bfee2916580dac4b008e595f437491d87abed02cefcd9db53d94d02daee67918e5d6787463183b4b87c1050000002f7809959bc048850613d17ca51055f2f416a44fe180d2d50c312cca7cb14a2bdc331f57a9817139a206fc76957227ffff2de20a4b8e3737fbb42913777c06376f799eba367e21f94ca598705f5dcb767d6f0900d6b0f6095e53c4c4234d0c1fbe434f6ab8f43c0013ee93b83946ee7759e89d7bdd1a32d7b311711b757fe43c06d21a35810d8fe98b27faea8aa12bc8716eefc5c97c45ac33eeec964c5214bc3a9359bdea1cccab94f15e36319cb34ebcacedb82c2ed3de692839d7961939adfdeeeaff19d11efcafb6d546fef271e89d6cc2389e81ff58cefcce3fbf4625a7e7de40e42e07b34449e15e065cc7340002000000000000f288a4510de03dab19d26285eda89156d50dd385a60333ba5bbf5d77cd7007ad1519ad5470de3dd6d6080cafccf8a97406bb6b68a1f0c4549820a73c880f475f732ae00398e8bd1f4108b7807fb33b72685ec37a2d3f766413a60459516246e5a1d998a2017aef0948a68cf255315ab80dd349e891aef595dc4d470e8ac32a308e15fc37d06aeac289c0523f483e1ff7408c6087f1ab652f2ef91d4f2b01987b0f46da034e5c3f745a7ee8101a3934c54e24b48ec0275e2d0687dc746b0827cbf652f406c6b95f2722e58c05f752ce2126596e1cd7655b904801784c416b22f73d324678e2724f43f1fe687c7e8a60c28b82b6528341b648cdd56fed7cdcbb15da202d5ecd36dea3bca0b7427d8392c6289455e8f8d2ab2242729251ae033a9e02210e62df0546a74b333a1c48f95fd54acb5741259e8c5488efeee327415cc19451432c6f14c27693102a3cd84857cd6586fc5ca9a93eb0145fac0662ff86107f998a8ef7df8aa14046c55b03d3d47f88a8d60f7774a2ee08758897fb411a94b3c2fc5d5f0db42c0456ec015f08e5247d33ae2d35603ff8454c16f8342856935125102bb784ed7148b6ce431b63ee356b0c785f2f47b90e29389f22fc5b59a70efaea2bd40195af4486220d702e30bfc43c10ec23ea6283994a7dde4dcb61fea6b651fb1d62458d0741a12830052fcc460db043afe525629b40d7cee458e4cb5e930ed624806c43a006e39336d07c2b8081c128ad2706f48261f7897484c297a1a6613bc18f5a38d442768af38041efe03d152ef95ff569e76db2391f4509d7f339d92fdb4a89364949da398000000000000000d80a4fe654578376e599aff3565b1d531f30912b9945030b81ea9935fd46edb44a78f615255490a4b621501f2a9e4d24624c4dac9274118c67584f5d374755534d7f68f679c4ff516a9c861a0e7e65868fcb2bf1cb9aea4e05df72279fdb0d2b9e935c5af3cf474bed79dfc248c1f5aea4b8b32c5d295e57079d0fe662a46b7f71cd47744db86c50b704c971d90295c7b2c7439a2d78ccfa79b5fc2bff6bbf840262bf89394b3e0691953264d2700c838fa2c7b3425260f59554e502dcea39cb313b0000000000004ca7c12f45858d6284ca6270d6b2f0e58fded8a7b4a302a97bc641df07720ba2b26bbfcc807ca0abb1b44322269c21c5ec68cb068ea88067d905ea917bb03eefdaebdeabf2d0dce80997c915c8949de992587c2cb5fe36d7d3e5db21b094b8b77940b5f07722e47a08d367e5f84c96ec664b72934b99b3109af65d77e86abd6859cddf4bbae1f0930462df15fddbc48562ea3511a8065ef028cf12f14dcf6ebecd8d884836174faf1aa609e5f1ee1162dfa13bdc1fa7cfaadba85c72e9758f03a755d0be53f8d2a1dfb1c68cc164b0a0780d971a96ea2c4d4ca0398c2235980a9307b3d5bd3b01faffd0a5dbed2881a9700af561ac8c6b00000000000000f96f06817fb903729a7db6ff957697c9ede7885d94ffb0969be0daf60af93109eb1dee72e4363f51af62af6fb2a6df3bec89822a7a0b678058fa3fef86faec216eb6992162f8dcbf719c148cd2f9c55f4901203a9a8a2c3e90f3943dbc10360a1a49700d1dfbf66d69f6fbaf506c8bcce8bb0d877a4eddd5d0fc5a752f9000", 0x1025}}, 0x1006)

[  631.839418][T16170] bond0: (slave bond_slave_0): Enslaving as an active interface with an up link
[  631.869537][T16170] bond0: (slave bond_slave_1): Enslaving as an active interface with an up link
[  631.938991][T16253] loop2: detected capacity change from 0 to 64
executing program 2:
close(0xffffffffffffffff)
openat(0xffffffffffffff9c, 0x0, 0x0, 0x0)
close(0xffffffffffffffff)
openat$cgroup_int(0xffffffffffffffff, 0x0, 0x2, 0x0)
bpf$BPF_BTF_GET_NEXT_ID(0x17, 0x0, 0x0)
bpf$BPF_BTF_GET_FD_BY_ID(0x13, 0x0, 0x0)
r0 = socket$inet6(0xa, 0x2, 0x0)
ioctl$sock_SIOCGIFINDEX(r0, 0x8933, &(0x7f0000000040)={'sit0\x00', <r1=>0x0})
ioctl$sock_inet6_SIOCSIFDSTADDR(r0, 0x8918, &(0x7f0000000080)={@loopback={0x0, 0x3fc}, 0x0, r1})

executing program 3:
io_setup(0x7ff, &(0x7f0000000040)=<r0=>0x0)
socketpair(0x1, 0x5, 0x0, &(0x7f0000000040)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff})
io_submit(r0, 0x1, &(0x7f00000014c0)=[&(0x7f0000000100)={0x0, 0x0, 0x0, 0x5, 0x0, r2, 0x0}])
syz_genetlink_get_family_id$mptcp(&(0x7f0000000080), r2)
write$binfmt_script(r1, &(0x7f0000000140), 0xa0)

[  632.282524][T16170] team0: Port device team_slave_0 added
executing program 1:
r0 = syz_mount_image$exfat(&(0x7f0000000040), &(0x7f0000000080)='./file0\x00', 0x2080004e, &(0x7f0000000240)=ANY=[@ANYBLOB='utf8,errors=continue,dmask=00000000000000000000007,umask=00000000000000000000006,dmask=00000000000000000000302,utf8,allow_utime=00000000000000000000120,uid=', @ANYRESHEX=0x0, @ANYBLOB="2c616c6c6f775f75746930303030a0ffffffffffffff3030313737372c00401c158afa9aee0579086fbf4f4e30babec44e828750ccebd5e6849023a36884d703d484ecb6a17b94186f318790ad4fb5cf3ff820d56078249fc971bba5fd8d00000000000000007a0cb052fe9812e5873433d3c278f7e4e88de5c0bf459b56b18c29b819653380dd76f4c85a3591d3f2703b694300cdeeecd8cb83c7b5748bf71f29d567ca440339fa"], 0x80, 0x1503, &(0x7f0000000580)="$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")
mkdirat(0xffffffffffffff9c, &(0x7f0000000340)='./file1\x00', 0x0)
r1 = openat$dir(0xffffffffffffff9c, &(0x7f0000000080)='./file1\x00', 0x0, 0x0)
ioctl$FS_IOC_SET_ENCRYPTION_POLICY(r1, 0x800c6613, &(0x7f0000000040)=@v2={0x2, @adiantum, 0x1b, '\x00', @auto="6fdf36bc70aef2303a2628d95de82ccb"})
sendmsg$nl_route(0xffffffffffffffff, 0x0, 0x0)
setsockopt$packet_add_memb(0xffffffffffffffff, 0x107, 0x1, 0x0, 0x0)
r2 = openat$uhid(0xffffffffffffff9c, &(0x7f0000000000), 0x2, 0x0)
write$UHID_CREATE(r2, &(0x7f0000002080)={0x0, {'syz1\x00', 'syz0\x00', 'syz0\x00', &(0x7f00000000c0)=""/42, 0x23}}, 0x120)
prctl$PR_SET_TAGGED_ADDR_CTRL(0x37, 0x1)
r3 = openat$vnet(0xffffffffffffff9c, &(0x7f0000000000), 0x2, 0x0)
ioctl$int_in(r3, 0x0, 0x0)
r4 = socket$packet(0x11, 0x0, 0x300)
r5 = fcntl$dupfd(r3, 0x0, r4)
ioctl$LOOP_SET_FD(r5, 0x4008af03, 0xffffffffffffffff)
r6 = syz_open_dev$tty1(0xc, 0x4, 0x1)
r7 = dup(r6)
write$UHID_INPUT(r7, &(0x7f0000001040)={0xf, {"a2e3ad21ed0d1bf91b29090955f70e06d038e7ff7fc6e5539b0d650e8b089b3f350763090890e0878f0e1ac6e7049b3346959b669a240d5b67f3988f7ef319520100ffe8d178708c523c921b1b5b31070d07580936cd3b78130daa61d8e8040000005802b77f07227227b7ba67e0e78657a6f5c2a874e62a9ccdc0d31a0c9f318c0da1993bd160e233df4a62179c6f30e065cd5b91cd0ae193973735b36d5b1b63dd1c00305d3f46635eb016d5b1dda98e2d749be7bd1df1fb3b231fdcdb5075a9aaa1b469c3090000000000000075271b286329d169934288fd789aa37d6e98b224fd44b65b31334ffc55cc82cd3ac32ecdb08ced6f9081b4dd0d8b38f3cd4498bee800490841bdb114f6b76383709d8f5c55432a909fda039aec54a1236e80f6a8abadea7662496bddbb42be6bfb2f17959d1f416e56c71b1931870262f5e801119242ca026bfc821e7e7daf2451138e645bb80c617669314e2fbe70de98ec76a9e40dad47f36fd9f7d0d42a4b5f1185ccdcf16ff46295d8a0fa17713c5802630933a9a34af674f3f39fe23491237c08822dec110911e893d0a8c4f677747abc360934b82910ff85bfd995083bba2987a67399eac427d145d546a40b9f6ff14ac488ec130fb3850a27af9544ae15ffffffffffffffff1243513f000000000000000a3621c56cea8d20fa911a0c41db6ebe8cac64f17679141d54b34bbc9963ac4f4bb3309603f1d4ab966203861b5b15a841f2b575a8bd0d78248ebe4d9a80002695104f674c2431dca141fae269cab70e9a66f3c3a9a63e9639e1f59c0ede26c6b5d74b078a5e15c31634e5ae098ce9ee70771aaa18119a867e14ffd9f9db2a7869d85864056526f889af43a6056080572286522449df466c632b3570243f989cce7cd9f465e41e610c20d80421d653a5520000008213b704c7fb082ff27590678ef9f190bae97909507041d860420c5664b27921b14dc1db8892fd32d0ad7bc946813591ad8deff4b05f60cea0da7710ac0000000000008000bea37ce0d0d4aa202f928f28381aab144a5d429a04a6a2b83c7068ae949ed06e288e810bac9c76600025e19c907f8ea2e2010000008271a1f5f8528f227e79c1389dbdfffe492f21579d2c15b8c70cdb1c332d86d87341432750861ec2bc3451edca194b221cfec4603d276bbaa1dfa6d4fb8a48a76eafc9a9a0270e4c10d64cd5a62427264f2377fe763c43470833ac96c45f357cbbaba8f1b1fdcc7cbb61a7cdb9744ed7f9129aede2be21ccfdc4e9134f8684b3a4f354da9a795e96334e207dff70f1988037b2ed3aaf575c0b88d8f146684078416d59fdee5325928974d12dad99dac44c3f0008047096a44002bebc2420aed92fa9b6578b4779415d4ac01b75d5495c118045651cf41c2fc48b778efa5ea5677747430af4162b987b80c3e001cd34e5c92f76cc4c24eeb8bc4e9ac2aed9e53803ed0ca4ae3a9737d214060005ea6f1783e287b3bee96e3a726eafe2fdfaa78d1f48c13b64df07847754b8400daaa69bf5c8f4350aeae9ca1207e78283cd0b20ceb360c7e658828163e2d25c4aa348561f927e88f63aa70e73a5e69b3df3495903f06572e1e007fa55a2999f596d067312f5779e8dbfdcf3427138f3d444d2639a10477f9bec4b0bbb6e3c04be68981f392203dd0ee3ef478e16dacfc5e3e03cf7ab8e3902f1b0ff034ef655b253ca509383815b1b6fc6522d4e4fdc11a48cf42d48604675fde2b94cf00500a2690891abf8ab9c015073014d9e08d4338b8780bdecd436cf0541359bafffa45237f104b96210403b2de9efed496f423500c7872c827467cfa5c4e72730d56bd068ed211cf847535edecb7b373f78b095b68441a34cb51682a8ae4d24ad0465f3927f889b813076038e79a7962fb385a882e8020f06c4c2ba1dd5cac7c18876da865d258734dd73583df292892448039ef799cf0630becdcce04579b5561dc825ab829827945e020c1f67ee615feb6243378e0610060f02cca4e91b2f001edb3d78fb4b55668dda93aec92a5de203717aa49c2d284acfabe262fccfcbb2b75a2183c46eb65ca8104e1b4da7fbb77ab2fc043aead87c32ab875ee7c2e7b7019c982cd3b43eaeb1a5fb135c0c7dcee8fe6516a328032f88c042891824659e9e94265c803b35ee5f83a2b210520106b8a358b50ab7a1fa89af9c251fe5294b3d1802d5676d95f160ec97b1ad94872cb2044642c37b4a6cc6c04effc1672db7e4b68d787d9a7a508ae54b3cd7369dde50e8c77d95a3d361c040babb171607caac2a3559ad4f75465f49c0d0ae3716db6e00cb11db4a5fade2a57c10238e204a67737c3b42aae501b20f7694a00f16e2d0174035a2c22656dc29880acebdbe8ddbd75c2f998d8ac2dfad2ba3a504767b6b45a45957f24d758ed024b3849c11d412a2a03b4047497022d9c30e23ef4df5c89644f48bb536f7945b59d7bcddff754413d135273ea8e75f22f216c6b9990ae71806f2c00b4025c48b75c0f73cdb9a7b8fa367b50028067e7f16f4dd569d462f4f19eacdb3ed70eeebb4483f8fd777d443e8b40427db6fe29068c0ca3d2414442e8f3a154704b0e51bc664a137b26be719f4f7c9a5678a674dfc95df80b9ce375dd649c8c704e509bd88c8e63d8c7dd67071115c8982ba46af4d6adcc9f68a75b9397b035153faf46366e7205dd8d6f37525c1a0e94610dd94323f6c15d085197149bfd6655548cfd9c52c9711937f79abb1a124f1210465483cd3b2d78378cfb85ed82e7da0f6eb6d279f2ae455925d0f6f1ba571eba281f2a654fb39ddff3b484439ff158e7c5419e037f3e3ad038f2211f1033195563c7f93cd54b9094f226e783271e1e5a2a2c10712eab625d64931cd4ffe6738d97b9b5ef828ee9fb059fc01af0e79c1e14b1d25988c69a399567c1d93768f7971d31488b8658a20878b7c1dd7ba02fc42939dde3d4a3339a65d507dc59c51097b40517705da56e9ebf0afa53282bf86dbb58c548069ff6eb95aade7cc66d7bbef724779ca1f731b3346ff177050373d79ff7b3e7f9bc0c1b4b266a8878b90baaa039d3e3b63979ac3df6e6f4859afd50238c7547a39b60810938044ae185d2ba3e00a4e73676864ae090d81eaee5ee6cf1d0ab378dd4dd891e937c2ea5410e0513005000000000000003911fab964c271550027697b52160687461602f88df165d884b36ec2b6c25a2f33c715687e9d4afb96d6861aca47da73d6f3144345f48843dd014e5c5ad8fe995754bd9cf32fce1e31919c4b2082fb0a30b9deae84bed4b28045634073c9c58c89d9e99c81769177c6d594f88a4facfd4c735a20307c737afa2d60399473296b831dbd933d93994ba3064279b10ea0c5833f41f157ea2302993dbe433b1aa3a3766d5439020484f4113c4c859465c3b415c3432f81db8719539d5bf372aaaea1cc43a6c5cbe59758bfee2916580dac4b008e595f437491d87abed02cefcd9db53d94d02daee67918e5d6787463183b4b87c1050000002f7809959bc048850613d17ca51055f2f416a44fe180d2d50c312cca7cb14a2bdc331f57a9817139a206fc76957227ffff2de20a4b8e3737fbb42913777c06376f799eba367e21f94ca598705f5dcb767d6f0900d6b0f6095e53c4c4234d0c1fbe434f6ab8f43c0013ee93b83946ee7759e89d7bdd1a32d7b311711b757fe43c06d21a35810d8fe98b27faea8aa12bc8716eefc5c97c45ac33eeec964c5214bc3a9359bdea1cccab94f15e36319cb34ebcacedb82c2ed3de5a8a8f0011e8f74e82d7f96093530e76692839d7961939adfdeeeaff19d11efcafb6d546fef271e89d6cc2389e81ff58cefcce3fbf4625a7e7de40e42e07b34449e15e065cc7340002000000000000f288a4510de03dab19d26285eda89156d50dd385a60333ba5bbf5d77cd7007ad1519ad5470de3dd6d6080cafccf8a97406bb6b68a1f0c4549820a73c880f475f732ae00398e8bd1f4108b7807fb33b72685ec37a2d3f766413a60459516246e5a1d998a2017aef0948a68cf255315ab80dd349e891aef595dc4d470e8ac32a308e15fc37d06aeac289c0523f483e1ff7408c6087f1ab652f2ef91d4f2b01987b0f46da034e5c3f745a7ee8101a3934c54e24b48ec0275e2d0687dc746b0827cbf652f406c6b95f2722e58c05f752ce2126596e1cd7655b904801784c416b22f73d324678e2724f43f1fe687c7e8a60c28b82b6528341b648cdd56fed7cdcbb1575912d5ecd36dea3bca0b7427d8392c6289455e8f8d2ab2242729251ae033a9e02210e62df0546a74b333a1c48f95fd54acb5741259e8c5488efeee327415cc19451432c6f14c27693102a3cd84857cd6586fc5ca9a93eb0145fac0662ff86107f998a8ef7df8aa14046c55b03d3d47f88a8d60f7774a2ee08758897fb411a94b3c2fc5d5f0db42c0456ec015f08e5247d33ae2d35603ff8454c16f8342856935125102bb784ed7148b6ce431b63ee356b0c785f2f47b90e29389f22fc5b59a70efaea2bd40195af4486220d702e30bfc43c10ec23ea6283994a7dde4dcb61fea6b651fb1d62458d0741a12830052fcc460db043afe525629b40d7cee458e4cb5e930ed624806c43a006e39336d07c2b8081c128ad2706f48261f7897484c297a1a6613bc18f5a38d442768af38041efe03d152ef95ff569e76db2391f4509d7f339d92fdb4a89364949da398000000000000000d80a4fe654578376e599aff3565b1d531f30912b9945030b81ea9935fd46edb44a78f615255490a4b621501f2a9e4d24624c4dac9274118c67584f5d374755534d7f68f679c4ff516a9cc8036cbd65868fcb2bf1cb9aea4e05df72279fdb0d2b9e935c5af3cf474bed79dfc248c1f5aea4b8b32c5d295e57079d0fe662a46b7f71cd47744db86c50b704c971d90295c7b2c7439a2d78ccfa79b5fc2bff6bbf840262bf89394b3e0691953264d2700c838fa2c7b3425260f59554e502dcea39cb313b0000000000004ca7c12f45858d6284ca6270d6b2f0e58fded8a7b4a302a97bc641df07720ba2b26bbfcc807ca0abb1b44322269c21c5ec68cb068ea88067d905ea917bb03eefdaebdeabf2d0dce80997c915c8949de992587c2cb5fe36d7d3e5db21b094b8b77940b5f07722e47a08d367e5f84c96ec664b72934b99b3109af65d77e86abd6859cddf4bbae1f0930462df15fddbc48562ea3511a8065ef028cf12f14dcf6ebecd8d884836174faf1aa609e5f1ee1162dfa13bdc1fa7cfaadba85c72e9758f03a755d0be53f8d2a1dfb1c68cc164b0a0780d971a96ea2c4d4ca0398c2235980a9307b3d5bd3b01faffd0a5dbed2881a9700af561ac8c6b00000000000000f96f06817fb903729a7db6ff957697c9ede7885d94ffb0969be0daf60af93109eb1dee72e4363f51af62af6fb2a6df3bec89822a7a0b678058fa3fef86faec216eb6992162f8dcbf719c148cd2f9c55f4901203a9a8a2c3e90f3943dbc10360a1a49700d1dfbf66d69f6fbaf506c8bcce8bb0d872a02238926407a4eddd5d0fc5a752f90000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400", 0x1000}}, 0x1006)
write$UHID_INPUT(r2, &(0x7f0000002b40)={0x8, {"626c19f324a6ea20b7a5576bc8fe240c3d403b2cbf6fa6910016e7ba42b451a482549922b40a827c53b0d1aaab1bc95079523b2435b3d192316d8ae82daea54f2a469318b7648845452516441160344160aa08129bbd228b02315dbfd9966ffb47494395d531bac43baf47479f7dea37a6d95d8180ba3faf0c46b690e0d517a8a29c18f1f2710a20541c86e33051db2a127b9f1349bb797f883142836a66f733be9b4b7036aa03554b792fff499ca68f62f3fadcbf8b091e8c04d3dfd59471586ff52b2f82682176ee2021630fd679500eca920e27fff4f5dd5de8837a93b153c77dd43f1c17aeac56330a278639dcb293fc71b06dbceb7e16502240b347f940fb28c6ca3246928ce3684256f06ef6664d3a0dd3fbd3541d9df6c45214c2c7616ed401093f38c9fc09b1c217b0a43363aeab8eb80c091434a7364980e3dad65662d51ba1f650eac60b5c8e53ef8a2fc61607840b823b2b4404da42e1bf09e3c393037fac5a42a0990e5663715190eb8de67204b8fdd2b785cb09dfc407ee7900c57d4de701ff5f745173476585aa4d80f65986778a174bb636c331078513739bb17eb527d1868a0a7e3c91ab79e2bf8c6ffaf74d9e2f49aad9532e1ddae2623569f7d72b3f3c5c13b4db648ad6670ab704f7d113d1f87396bb9ee88cd627d095c8a1cd9c10fd434701b4886ab5254d68544b99bd0e5ecb0d40a44af746e675f88cdde900e10c9df042fd8bc5696e0579aa4b2ba5209c9bdb1f15f65b82dd17bf44dab001828535022da68a80bf6d5e2382aa38162090b83934fc5409acf739fc86a91c2fb33c0dbbb82d9dc4af2743bfa4534b00c95c41693e69e0f62c811d913330fba8b26c5be2e95b450ae0e4162103cf2f3e1b01d4a1b0f510a626a2346ee18094b9c27f4f0b359cb38be0d03ff25200a2829bd39190e1db5c74142bf978c789713edb135d91dc4d074367b954d446ba9051e5f3128c3cdcfc6b42e8dd06d5b290cc7f58f38559209bcd9ac519080fc67857e67eeb69596b6c4460ed10ad531ce9c485dc18c7b2428219ddb251e31168b41758897ccc794437f3d0ad590c03a0bccf6712b317866fa49493ed76d8ec87b9a88cea2a29f416dd615adbc7746ed67bae0d411389fb40780531fb2e268ad7e9d800767a1260162a051471c126a157ea542dce3d0e6c3f24db4289aaccf9f8598aeb9eba240bda6e500ba8683ee76a1d7d475be925d180c0d06422e86bcc4003f67c068af9d9aeae5acda84585f504d86e77e5fede52730cc14a5905e3197038a1c2d6b3f6427f1c9665b627a1c86ea198d286999cec702f4bff44f110804b95f3790758616b1e2fc74d4b7de8d7c566eb93858d21e3a04d4dfb2e75c478d96a8d9f37debe8e39e5a2bc14c5df865cae7a5745f33ddda0d1f2efae6e0606d99373dcd1924f8be44a072c504e0361c790869ee294fb090aefb1d59039c907faee5affb1bc8c6bb58c7e76f523e0cfc3b2f9e5e9fddf0559a1b3c86592cb6b40ea4ca681d8cf28e4cc4f2d0291f6c75773fad544bd7cc7e980df2b61d915713a14f8b3f9dc7eb3b6376bc2b88136aae2f83a96898efd2197a0d8bf1022128a130f3d1ae236083ac8dc42ad7ce22c467c42857cb109b8a0642f6ec82ccbc82f2e1bf9ff2f1e32daa77cb8b984568c8c369febddd0926b24e044cbbda975cbf4136f6bf514efd706cc665ccc1cd524407bf44760d5e942bdb1290fab636d81b7060482ec68263e16f44674f0309c57440d922d0cef43145a41c4c573fb0618df28de4a4de9d5d4193915e51de826359078186e8739626e9c9328b2c1812494bdf1187579b16ed0d705753299b3960f7b97c76db3f33616ad0782274390fe32a6481b9978d052574a729d01a1d912e6e755046f28bf498b11aafda9017ee5a35f7c6fcb83521037c0fedc518d846edcb62d0a7c0b661063ee584bca5838906ebe638b8425c1b28313fef8fab3868591e905c11d7f2d6c3249b3cd0d3edba26c03305542fcf6c36aceca6943df89526c1f198348c83d3d8b72ff82bf4163514f84e5c08b8a97f49e4693314f7426e85c361291b7c7de39c058c69dcb7fb487a2654372704eebcfc3f16b0cf6b7f1e9638690757b67ea4679b122b591cdf613b6c87dae5504c0e5869477d72a7c9b9dcf8781c1b1d0e785c244488514290ff9a681256c9175df9bcd8ccb5a75fd3e69fc5a24dcacfb07d25271255371600f780fe9e62567a591b1c45093aa3f3b096f858f55c273de6b0d30f71b648daf0fe019c07ac8e040bb0fd46f5cb22afa4f82466aef020eae174d1a41b0b0b2e1c64e75d7a487092dc7f37c187ad6c1c07b185f31705d706d23a1b8dcb4b1c15f4551f0d1d352689e58fc95171503fb10cfd26ac4772a2b87ba728a534ea995a5b89ec3a734123641a5bbf142a96b4478c39afb327c20561419951535e66bf06096387270464fab9afee6748834094a4761e0cd1ea7c9ee2257a36f2720d9d42283ba1891a18974aa861d21202edb6f1623829fec67698c26962c0a66d84295d4f16792e2f6edb6c5bfbe8c8eaba45130ff343922756dcc675f21587fb5db06d96bbf21025ea6c8152245e846b79943a1fd67bd1d7c133156e8a50c0514591e3a42214fae6e9f105cb33f27690d018276d6457092d8e9501aa329ab67980e74ac1fe4403783657cc01de8251fb7e2496678d6c90c9e113bfc63dda1839ba21a51bfaebfa84d09d541c07aeb2a7ab6529b712b3846d6437b27e7e30e4015bf047af57231e63443ad7d98f1338930a0361a139555f1b1b01d9d5208a9498d74c37d0831585fbe014518c79ca8142ee01f76e52722783163cfd90630302856424726eacee4fd74eac5e4e6c271399063b95d74f0da3215ea52b1e8118f21a3ed1dd268730785acf3f3241b34729d9727b6bbbc4e9ea473adb495ff7f16532b762306b8a1997d94e6bbb8362213c48bac93f7c2ce46b177da0eb35b9cf70bfc496739b5b42f3accd117f23c6f3983dd3fd5b9d811a8d16f1f70f7e275846fee212b926f7dc696fe6a5f2fb570b577c20e0cb2161b3e6414306184926f5a4a72294359de88bfb03205b7ccae272d342ddadd23c1443e156bc0e8404ff072078f0765627b8bebb30fb7843636bb536af23fba54fc3bdd21e942f1c5cbb232e33ae282fd68886cf979badde591ce21241f4e353f956863c9bc2f6e68b97f795dc5ef3f64c7d6f8f5ca990227d59b47452b515217f854925b289f717f577115c0e3250971fc38970e444b2cf76dd954398ce865e06d63a684a603080db9316a580987884cf42ebee4f41f48b27b73084a5c76be85e786c041468209135ba649339e60ce16b2db60e73bec8595d07cbc26e76b5f8abc54a197a458f8ae1e46d511c57213c7206af49fbe26e52fb66e04301340522bc6a89f3c04cbd1bf510ef06b53c8e77772371e9d0bdc4583ca7bb511e4b6ca41c19ba53bc3635ca071ba2d428d4b151f4510f2adb57b1c9b80765a7f09127d3ca7ec1dc39d5fd12760e223eb7966ecd9393d72618665020eaef1d1eac68449fad331950a0bb4b641c23352bcc63aa0f4ee5411b1d391702ee3a5aaf313188bb190001ccf3946c1e90be4db5d0530cb47892a3bc69ed61c09708afb456019401c07512948bf62e97e001622e1ae4f656e12c5c36485eb1bcfa96145983928fe6e7316a7f048c3f84ee3ac9b5f8ca49ca953cb84352b0b67f0d5cddfda9757bd43068c0d75d18e9e6ea7609d6013043ec7fec4da4e8a977c13e290e46c397c2ecf16be0e674d72bbe4afccc230a737460acd5f253423bf8308e264d27b17e6c0aa46b8e996781a90a11fc187b25b4bef7ff5f0d6710ddb56980fab3e0a826305ed31eee162cd2573ff1105e548a034a4ecba6e821b2efd8f8798165ae5f9851902f577a28691e7e9957e083b441309dd288293e2c710c2806569f0687f96a35e61392d697c71bbd2c01f55ac39fa797a063c7cb42b86bd7df7a55e4ece9dc085c882674b2409909be8bca36d3528e217a8a5734aa3029c477b4d213b422fe38ffad7768e7f93f454d54e22bf0a88798dc6446c0c72894aebceea2bf1c6b0dfbb95fde527acd49d8abe61eb8dc200a0c9ba7c9d9a52c1fd850b47fb9a294879e5ab2ba448805192a435444ce9eef4c2c822fed5a3038795253757b7171ea766bc2e918ea16bb62cd3dfae2c9870dce6fd7285a7a02583fdb0601ddce76e1dbad5acd496887ac9068974dfe4bd047d962a2657258d9f88b2542a6d1635f989f2606a945aab86e6ffbce0958881aeaee1fd8c391415ad63d76bb411341a20fade4a9ec327cfa62b6c62f21f9633f6cbacc3a3722cda1ef88e57523679d5b64b78b522f25a40528b57e4dddac94ac835899abe05f5c9d2890b9f4ad98e8d33b972dceada3a7e5557b9de0aae9fdd017dd0d87e4fe82761110423387af816d222132b1ec6613c45b84a34f7b2c688f7f77c2644c038acc682f1a7fb495d31eddc40bcd00ba6e55ab4ab7c85226adc4879ade8f870ee08ce6c6d624e9789e42217f2303c39a6c5ebc77fe408e3f316a4c2440f0ffa15c3cd771d1ca8ac8e062fc89a2a04ff931c72b3216b57c0bb3cfb725b82d470afe4121246196c05c351f780ab6640e4668ddb12439703f72f47dc30d0fd2ecaba8ece466a079e45680499956f8c444523ab8dc8f3788b7698e6756bea5d408f9a99dc818105729e5ea1b659d099f491538ea7446c8d68581cc276ebf064709075756e4f1adf7cf335af444e4e8b8f36a77c5bba73a11d5315d2a13d979a5f7ebc028f18d81e47fb161e74a5db3211abb965991de4c4428e2732104b9d19679b7b8dc2033642da56019525b77c44a9ac0c5cb5561eda639eb6935acff3e861435649e8f6fc26c9a65dad0c2c09a8c06eff6e9cc2c142b07156946d9ca4b875a945184e36b24ece33d5bac7837dd90df521c1986a02dc7e93395006cf9154a6a29ae5de70392cb3525be585755807ad78b93036a5b77c5eb9eeb246b949cd651688691470377aefbb0e4eee42edfe8ebc6c2645fa1949b6caddd9e07f92e211ebe5482e8b785496675d070330419732d7171563e30bf6e4575b631e4c84f6f0191ff317599896fb7f8d154b694b5af9ca3cfc5c6e0bfa740475e35d264bdbc5a44c55e0322627b2516e35cd7f88365e874d622dfb7bca3edd2f0cea20687fa43d86d75d277436fbbb63dd7e8901bf0cc2dbcd181ae7131da4a0cacaae513a4a9e75dee6c1f568b3f12cea4dccacdec39cc2aca0a1d506d468845e2add0488f7a8956180a0e6f9bda98728b780c7c37fd6e58bd0996baa0195bbccb144aac29946a2e7448912fd25dbc4262c478c61604c88f49a89ecbe4e1e2fa35f325d50779c80879da4070514e89e11c939e986070bdb74309455405de2d1b3113252fdf8a380399d6217c2f544d10ca17aaa97e1a50758fb4ff7cf1552a4597a5fb21508e2bc2a27a9fd78fba8a852e4c9b2c4db57a6fa055af09c8d2bc66a461b667925b4590a42c775aa40dd090e79cdb29020e84fda1dd3abb19d4b37e4a0b8ddc9c6f8202ae4af01ed689d7ee565bbb95d10f7cb2d1bc9b5dd8f177ed9c86eee715081374a1c32f964075253e5181939e171f11ad0995a6213bcc8c4cd28e4660c5c7f9e51c578c01c02ea87f904060f1533b00e2f7e64652888e4dc9874549a2f5efa63a88e07db4600022ae0842d88536fa5a3583e6263759cdc6e1ff62030eea5b69570eb96afb565abcc3bcf69da1dbe770b1d", 0x1000}}, 0x1006)
r8 = socket$vsock_stream(0x28, 0x1, 0x0)
ioctl$FS_IOC_GET_ENCRYPTION_KEY_STATUS(r0, 0xc080661a, &(0x7f0000000100)={@id={0x2, 0x0, @auto="e4776dacb8a23768fa7d54418ba244ff"}})
connect$vsock_stream(r8, &(0x7f0000000000)={0x28, 0x0, 0x0, @local}, 0x10)
bind$vsock_stream(r5, &(0x7f0000000280)={0x28, 0x0, 0x0, @hyper}, 0x10)
mmap(&(0x7f0000ffc000/0x4000)=nil, 0x4000, 0x0, 0x10, 0xffffffffffffffff, 0x0)

[  632.440499][T16170] team0: Port device team_slave_1 added
executing program 4:
openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000280)='cgroup.controllers\x00', 0x275a, 0x0)
bpf$PROG_LOAD(0x5, 0x0, 0x0)
r0 = bpf$MAP_CREATE(0x0, &(0x7f00000009c0)=@base={0x0, 0x0, 0x4}, 0x48)
close(0xffffffffffffffff)
bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x11, 0xc, &(0x7f0000000440)=ANY=[@ANYBLOB="18000000000000000000000000000000181100", @ANYRES32=r0], 0x0, 0x0, 0x0, 0x0, 0x41100, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
syz_mount_image$ext4(&(0x7f0000000040)='ext4\x00', &(0x7f0000000200)='./file1\x00', 0x200000, &(0x7f0000000f80)={[{@grpquota}, {}, {@nombcache}, {@norecovery}, {@debug_want_extra_isize={'debug_want_extra_isize', 0x3d, 0x80}}, {@lazytime}, {@nodelalloc}, {@noblock_validity}, {@noauto_da_alloc}]}, 0xfe, 0x54c, &(0x7f0000000400)="$eJzs3d9rW1UcAPDvTdv91nUwhvoghT04mUvX1h8TfJiPosOBvs/Q3pXRZBlNOtY6cHtwL77IEEQciH+A7z4O/wH/ioEOhoyiD75EbnrTZWvSZm22Zubzgduec+9Nzz0593t6Tk5CAhhaE9mPQsSrEfFtEnG47dho5Acn1s5bfXh9NtuSaDQ++yuJJN/XOj/Jfx/MM69ExG9fR5wsbCy3tryyUCqX08U8P1mvXJmsLa+culQpzafz6eXpmZkz78xMv//eu32r65vn//nh07sfnfnm+Or3v9w/cjuJs3EoP9Zejx240Z6ZiIn8ORmLs0+cONWHwgZJstsXwLaM5HE+FlkfcDhG8qgH/v++iogGMKQS8Q9DqjUOaM3t+zQPfmE8+HBtArSx/qNrr43Evubc6MBq8tjMKJvvjveh/KyMX/+8czvbon+vQwBs6cbNiDg9Orqx/0vy/m/7TvdwzpNl6P/g+bmbjX/e6jT+KayPf6LD+Odgh9jdjq3jv3C/D8V0lY3/Pug4/l1ftBofyXMvNcd8Y8nFS+U069tejogTMbY3y2+2nnNm9V6j27H28V+2ZeW3xoL5ddwf3fv4Y+ZK9dJO6tzuwc2I1zqOf5P19k86tH/2fJzvsYxj6Z3Xux3buv7PVuPniDc6tv+jFa1k8/XJyeb9MNm6Kzb6+9ax37uVv9v1z9r/wOb1H0/a12trT1/GT/v+Tbsd2+79vyf5vJnek++7VqrXF6ci9iSfbNw//eixrXzr/Kz+J45v3v91uv/3R8QXPdb/1tFbXU8dhPafe6r2f/rEvY+//LFb+b21/9vN1Il8Ty/9X68XuJPnDgAAAAAAAAZNISIORVIorqcLhWJx7f0dR+NAoVyt1U9erC5dnovmZ2XHY6zQWuk+3PZ+iKn8/bCt/PQT+ZmIOBIR343sb+aLs9Xy3G5XHgAAAAAAAAAAAAAAAAAAAAbEwS6f/8/8MbLbVwc8c77yG4bXlvHfj296AgaS//8wvMQ/DC/xD8NL/MPwEv8wvMQ/DC/xD8NL/AMAAAAAAAAAAAAAAAAAAAAAAAAAAEBfnT93Ltsaqw+vz2b5uavLSwvVq6fm0tpCsbI0W5ytLl4pzler8+W0OFutbPX3ytXqlanpWLo2WU9r9cna8sqFSnXpcv3CpUppPr2Qjj2XWgEAAAAAAAAAAAAAAAAAAMCLpba8slAql9NFCYltJUYH4zIk+pzY7Z4JAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB75LwAA///MUDi3")
bpf$PROG_LOAD(0x5, 0x0, 0x0)
bpf$MAP_CREATE(0x0, 0x0, 0x0)
bpf$MAP_DELETE_ELEM(0x2, &(0x7f0000000400)={0xffffffffffffffff, 0x0, 0x20000000}, 0x20)
syz_emit_ethernet(0x3e, &(0x7f0000000000)=ANY=[@ANYBLOB="0180c200de00ba8d7061966c86dd60bc426000082c00fc000000000000000000000000000000ff0200000000000000000000000000013b000001"], 0x0)

executing program 2:
io_uring_setup(0x177f, &(0x7f0000000140))
socket(0x2b, 0x1, 0x0)
open_tree(0xffffffffffffff9c, &(0x7f0000000640)='\x00', 0x89901)
r0 = openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000080)='cgroup.controllers\x00', 0x275a, 0x0)
ioctl$FS_IOC_GETFSMAP(r0, 0xc038586a, &(0x7f0000000600)=ANY=[@ANYBLOB="05"])

[  632.577735][T16264] loop1: detected capacity change from 0 to 256
[  632.602196][T16264] exfat: Deprecated parameter 'utf8'
[  632.622516][T16264] exfat: Deprecated parameter 'utf8'
[  632.637480][T16264] exfat: Unknown parameter 'allow_uti0000��������001777'
[  632.689915][T16170] batman_adv: batadv0: Adding interface: batadv_slave_0
[  632.711351][T16266] loop4: detected capacity change from 0 to 1024
[  632.719447][T16170] batman_adv: batadv0: The MTU of interface batadv_slave_0 is too small (1500) to handle the transport of batman-adv packets. Packets going over this interface will be fragmented on layer2 which could impact the performance. Setting the MTU to 1560 would solve the problem.
executing program 3:
setsockopt$inet6_mtu(0xffffffffffffffff, 0x6, 0xd, 0x0, 0x0)
mmap(&(0x7f0000ff4000/0xb000)=nil, 0xb000, 0x0, 0x219adcebc81d632, 0xffffffffffffffff, 0x0)
socket$unix(0x1, 0x1, 0x0)
r0 = socket$inet(0x2, 0x1, 0x0)
close(r0)
sched_getparam(0x0, 0xfffffffffffffffc)
r1 = socket$unix(0x1, 0x1, 0x0)
bind$unix(r1, &(0x7f0000003000)=@file={0x1, '\xe9\x1fq\x89Y\x1e\x923aK\x00'}, 0x6e)
listen(r1, 0x0)
r2 = accept4$inet6(r0, 0x0, 0x0, 0x0)
r3 = socket$unix(0x1, 0x1, 0x0)
socket$unix(0x1, 0x1, 0x0)
connect$unix(r3, &(0x7f0000000000)=@file={0x1, '\xe9\x1fq\x89Y\x1e\x923aK\x00'}, 0x6e)
socket$nl_route(0x10, 0x3, 0x0)
write$P9_RGETATTR(r2, 0x0, 0x0)

[  632.774649][T16266] EXT4-fs (loop4): mounted filesystem 00000000-0000-0000-0000-000000000000 r/w without journal. Quota mode: writeback.
[  632.774953][T16170] batman_adv: batadv0: Not using interface batadv_slave_0 (retrying later): interface not active
[  632.830222][T16170] batman_adv: batadv0: Adding interface: batadv_slave_1
[  632.847355][T16264] fscrypt (sda1, inode 1949): Mutually exclusive encryption flags (0x1b)
executing program 4:
syz_mount_image$fuse(0x0, &(0x7f0000000080)='./file0\x00', 0x0, 0x0, 0x0, 0x0, 0x0)
mount(0x0, &(0x7f0000000000)='./file0\x00', &(0x7f00000000c0)='mqueue\x00', 0x0, 0x0)
chdir(&(0x7f0000000380)='./file0\x00')
ioperm(0x0, 0x4, 0x7)
msgctl$IPC_SET(0x0, 0x2, 0x0)
add_key$fscrypt_v1(0x0, &(0x7f0000000180)={'fscrypt:', @desc1}, &(0x7f00000001c0)={0x0, "cb96a945ab526fe377145584b62491050e011fd59d1396798a98902d3fafc9e09a29e6671ad9f5f25693b12e5d0ac30e15fd59e58f7200"}, 0x48, 0xfffffffffffffffe)
pipe2$watch_queue(&(0x7f0000000280), 0x80)
mount$9p_fd(0x0, 0x0, 0x0, 0x0, &(0x7f0000000940)={'trans=fd,', {}, 0x2c, {}, 0x2c, {[{@msize}, {@nodevmap}, {@version_L}, {@nodevmap}, {@access_user}, {@privport}, {@cache_mmap}, {@privport}], [{@seclabel}, {@smackfstransmute={'smackfstransmute', 0x3d, '[\x8a'}}]}})
openat(0xffffffffffffff9c, &(0x7f0000000040)='.\x00', 0x0, 0x0)
openat(0xffffffffffffff9c, &(0x7f0000004280)='./file0\x00', 0x0, 0x0)
r0 = openat$cgroup_ro(0xffffffffffffffff, 0x0, 0x275a, 0x0)
ioctl$EXT4_IOC_SETFSUUID(r0, 0x4008662c, 0x0)
bpf$PROG_LOAD(0x5, 0x0, 0x0)
openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000280)='cgroup.controllers\x00', 0x275a, 0x0)

[  632.867003][T16170] batman_adv: batadv0: The MTU of interface batadv_slave_1 is too small (1500) to handle the transport of batman-adv packets. Packets going over this interface will be fragmented on layer2 which could impact the performance. Setting the MTU to 1560 would solve the problem.
[  632.985324][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.985534][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.985563][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.985589][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.985614][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.985639][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.985663][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.985688][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
executing program 3:
socket$inet6_tcp(0xa, 0x1, 0x0)
r0 = openat$rtc(0xffffff9c, &(0x7f0000000040), 0x0, 0x0)
ioctl$BTRFS_IOC_TREE_SEARCH(r0, 0x7005, 0x0)
r1 = syz_io_uring_setup(0x2ddd, &(0x7f00000006c0)={0x0, 0x0, 0x10100}, &(0x7f00000003c0), &(0x7f0000000440)=<r2=>0x0)
syz_io_uring_setup(0x5c4, &(0x7f0000000200), &(0x7f0000000140)=<r3=>0x0, &(0x7f00000002c0))
syz_io_uring_submit(r3, r2, &(0x7f00000001c0)=@IORING_OP_POLL_ADD={0x6, 0x0, 0x0, @fd_index=0x4})
io_uring_enter(r1, 0xa3d, 0x0, 0x0, 0x0, 0x0)
socketpair$unix(0x1, 0x5, 0x0, &(0x7f0000000000)={<r2=>0xffffffffffffffff, <r3=>0xffffffffffffffff})
sendmmsg$unix(0xffffffffffffffff, &(0x7f0000004080)=[{{0x0, 0x0, 0x0, 0x0, &(0x7f0000000280)=ANY=[@ANYRES64=r0, @ANYRES16=r3], 0x18}}], 0x1, 0x0)
r4 = dup3(r2, r2, 0x80000)
connect$unix(r4, &(0x7f0000000100)=@abs={0x1}, 0x6e)
mkdirat(0xffffffffffffff9c, &(0x7f0000000080)='./file0\x00', 0x200)
r5 = syz_io_uring_setup(0x74df, &(0x7f0000000300)={0x0, 0x1, 0x2, 0x0, 0x0, 0x0, r4}, &(0x7f0000004000), &(0x7f00000004c0))
io_uring_register$IORING_REGISTER_PERSONALITY(r5, 0x9, 0x0, 0x0)
r6 = openat$cgroup_ro(0xffffffffffffff9c, &(0x7f00000001c0)='pids.current\x00', 0x275a, 0x0)
mmap(&(0x7f0000000000/0xb36000)=nil, 0xb36000, 0x2, 0x28011, r6, 0x0)
ftruncate(r6, 0xc17a)
r7 = io_uring_register$IORING_REGISTER_PERSONALITY(r5, 0x9, 0x0, 0x0)
io_uring_register$IORING_UNREGISTER_PERSONALITY(r5, 0x13, 0x2000ac0a, r7)
mknod(&(0x7f0000000040)='./file0\x00', 0x8001420, 0x0)
r8 = open$dir(&(0x7f0000000100)='./file0\x00', 0x149800, 0x0)
ppoll(&(0x7f0000000080)=[{r8}, {r8}], 0x2, 0x0, 0x0, 0x0)
open(&(0x7f0000000200)='./file0\x00', 0x2, 0x0)
bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x11, 0xb, &(0x7f0000000180)=ANY=[@ANYBLOB="18000000000000000000000000000000180100002020702500000000002020207b1af8ff00000000bfa100000000000007010000f8ffffffb702000000000000b7030000000000f7850000002d00000095"], &(0x7f0000000040)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
r9 = bpf$MAP_CREATE(0x0, &(0x7f00000009c0)=@base={0x19, 0x4, 0x8, 0x8}, 0x48)
r10 = bpf$PROG_LOAD(0x5, &(0x7f0000000500)={0x11, 0xc, &(0x7f0000000440)=ANY=[@ANYBLOB="1c001104001000000000001b0000000000000000", @ANYRES32=r9, @ANYBLOB="0000000000000000b7080000000000107b8af8ff00000000bfa200000000000007020000f8ffffffb703000008000000b70000000000925e850000000100000095"], &(0x7f0000000240)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$MAP_UPDATE_ELEM_TAIL_CALL(0x2, &(0x7f0000000400)={{r9}, &(0x7f0000000380), &(0x7f00000003c0)=r10}, 0x20)
r11 = socket$inet6_icmp_raw(0xa, 0x3, 0x3a)
r12 = dup2(r11, r11)
setsockopt$inet6_IPV6_HOPOPTS(r12, 0x29, 0x36, &(0x7f0000000040), 0x8)
setsockopt$inet6_IPV6_RTHDR(r12, 0x29, 0x39, 0x0, 0x0)

[  632.985713][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.985737][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.985759][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.985784][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.985816][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.985920][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.985947][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.985972][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.985996][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.986021][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.986045][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.986069][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.986094][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.986118][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.986142][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.986175][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.986199][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.986224][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.986249][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.986273][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.986298][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.986321][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.986346][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.986370][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.986394][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.986419][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.986444][T14980] hid-generic 0000:0000:0000.0009: unknown main item tag 0x0
[  632.997126][T16170] batman_adv: batadv0: Not using interface batadv_slave_1 (retrying later): interface not active
[  633.010580][T15853] EXT4-fs (loop4): unmounting filesystem 00000000-0000-0000-0000-000000000000.
[  633.090020][T14980] hid-generic 0000:0000:0000.0009: hidraw0: <UNKNOWN> HID v0.00 Device [syz1] on syz0
[  633.218441][T16170] hsr_slave_0: entered promiscuous mode
[  633.263360][T16277] kernel read not supported for file /cgroup.controllers (pid: 16277 comm: syz-executor.4)
[  633.263590][   T29] audit: type=1800 audit(1715377312.784:984): pid=16277 uid=0 auid=4294967295 ses=4294967295 subj=_ op=collect_data cause=failed comm="syz-executor.4" name="cgroup.controllers" dev="mqueue" ino=60805 res=0 errno=0
[  633.266796][T16170] hsr_slave_1: entered promiscuous mode
[  633.276262][T16170] debugfs: Directory 'hsr0' with parent 'hsr' already present!
[  633.276417][T16170] Cannot create hsr debugfs directory
[  633.796341][ T5093] Bluetooth: hci2: command tx timeout
[  634.091277][T16268] loop2: detected capacity change from 0 to 32768
[  634.159001][T16268] XFS (loop2): Mounting V5 Filesystem bfdc47fc-10d8-4eed-a562-11a831b3f791
[  634.358101][T16268] XFS (loop2): Ending clean mount
executing program 4:
r0 = syz_init_net_socket$nl_generic(0x10, 0x3, 0x10)
ioctl$sock_SIOCGIFINDEX_802154(r0, 0x8933, &(0x7f0000000000)={'wpan1\x00', <r1=>0x0})
r2 = syz_genetlink_get_family_id$ieee802154(&(0x7f0000000080), r0)
r3 = syz_init_net_socket$nl_generic(0x10, 0x3, 0x10)
sendmsg$IEEE802154_LLSEC_DEL_KEY(r3, &(0x7f0000000740)={0x0, 0x0, &(0x7f0000000700)={&(0x7f0000000680)={0x34, r2, 0x1, 0x0, 0x0, {}, [@IEEE802154_ATTR_PAN_ID={0x6}, @IEEE802154_ATTR_LLSEC_KEY_MODE={0x5}, @IEEE802154_ATTR_DEV_INDEX={0x8, 0x2, r1}, @IEEE802154_ATTR_SHORT_ADDR={0x6}]}, 0x34}}, 0x0)

executing program 1:
r0 = openat$udambuf(0xffffffffffffff9c, &(0x7f00000000c0), 0x2)
ftruncate(r1, 0xffff)
fcntl$addseals(r1, 0x409, 0x7)
r2 = ioctl$UDMABUF_CREATE(r0, 0x40187542, &(0x7f0000000000)={r1, 0x0, 0x0, 0x10000})
mmap(&(0x7f0000ffa000/0x2000)=nil, 0x2000, 0x0, 0x11, r2, 0xffffc000)
syz_open_dev$MSR(&(0x7f00000001c0), 0x0, 0x0)
openat$binder_debug(0xffffffffffffff9c, 0x0, 0x0, 0x0)
syz_mount_image$hfs(&(0x7f0000000140), &(0x7f0000000280)='./bus\x00', 0xc090, &(0x7f0000002700)=ANY=[], 0xff, 0x266, &(0x7f00000003c0)="$eJzs3c9qE10Yx/HfmeR9jbbU6R8RxFW14ErauhE3guQO3LgStYlQDBW0grqqrsULcO8teBGuxLXgzpUXkF3kPHNiJmkmE0PTk6TfDyQknfPMPCdzpuc8U0oE4My6V//5+dYv/3BSRRVJd6REUk2qSrqky7VXB4f7h61mY9SOKhbhH05ZpDvWZu+gOSzUx1lEkPp3VS3nf4bpqP2InQFmgV39QyTSuXB12vbaqWc2HUexE4jMtdXWa63EzgMAEFeY/5Mwzy+H9XuSSFth2u+f/+d8Am3HTiCy3PxvVVbH+fN70Tb16j0r4fz2pFslTnKs/5WNrL4FpiurKi2X5PzT/Vbz5t7zViPRe90Ncs027LmRDd2ufLbvju96c0htOsLkfV+yPvzn+7BbkP/6yR6xnPvqvrmHLtUnNf6u/6od50+Tnal04Exl+W8X79F6mWatCnq5age5Eo4QjOxlRQUVibojalX9NwjSsjwtam0gKuvdTknU+tCo3ZKojcGo3mgujpw299E9cJv6rS+q59b/if+0tzTOlenbWMswMkb2p2otU5tPwlV3dHVoy2TSHmECH/REt7Xy8s3bZ49breYLXpyhF91BMCv5LOwL/yFHOXp33pl8P9F+M+EU9U76Pwbyt5lF4dddLqv/cvXKti3W/FM6Yp3eKdt5bo87BbXBmj1fKK7g+ji79bBUXMGNW3NduyFdH+eImTTkuSBcXd/1iPv/AAAAAAAAAAAAAAAAAAAA8+bk/uWgpqJNsfsIAAAAAAAAAAAAAAAAAAAAAMC8m7nv/72v7B3f/wtM3Z8AAAD//9YVdvU=")
r3 = openat(0xffffffffffffff9c, &(0x7f0000000040)='.\x00', 0x0, 0x0)
capset(&(0x7f0000000300)={0x20071026}, &(0x7f0000000340))
r4 = openat$binder_debug(0xffffffffffffff9c, &(0x7f0000000040)='/sys/kernel/debug/binder/transactions\x00', 0x0, 0x0)
read$FUSE(r4, &(0x7f0000000480)={0x2020, 0x0, 0x0, 0x0, <r5=>0x0}, 0x2020)
fchown(r3, 0xffffffffffffffff, r5)
openat$fuse(0xffffffffffffff9c, 0x0, 0x42, 0x0)
llistxattr(0x0, 0x0, 0x0)
socket$nl_generic(0x10, 0x3, 0x10)
r6 = socket$netlink(0x10, 0x3, 0x0)
r7 = socket$inet_udplite(0x2, 0x2, 0x88)
ioctl$sock_SIOCGIFINDEX(r7, 0x8933, &(0x7f0000000340)={'bridge_slave_0\x00', <r8=>0x0})
sendmsg$nl_route(r6, &(0x7f00000003c0)={0x0, 0x0, &(0x7f0000000200)={&(0x7f0000000000)=ANY=[@ANYBLOB="3402fbe6f8460cc2cc0000000000000007000000", @ANYRES32=r8, @ANYBLOB="000000000000000014001a80100004800c00038044fd000000000000"], 0x34}}, 0x0)
r9 = syz_open_dev$tty1(0xc, 0x4, 0x1)
r10 = dup(r9)
write$UHID_INPUT(r10, &(0x7f0000000000)={0x12, {"a2e3ad21ed0d09f91b5b090987f70906d038e7ff7fc6e5539b0d3d0e8b089b323b6d07060890e0878f0e1ac6e7049b334a959b3e9a240d5b67f3988f7ef319520100ffe8d178708c523c921b1b5b31070b07580936cd3b78130daa61d8e8040000005802b77f07227227b7ba67e0e78657a6f5c2a874e62a9ccdc0d31a0c9f318c0da1993bd160e233df4a62179c6f30e065cd5bcd0ae193973735b36d5b1b63dd1c00305d3f46635eb016d5b1dda98e2d749be7bd1df1fb3b231fdcdb5075a9aaa1b469c3090000000000000075271b286329d169934288fd789aa37d6e98b224fd44b65b31334ffc55cc82cd3ac32ecdb08ced6f9081b4dd0d8b38f3cd4498bee800490841bdb114f6b76383701d8f5c55432a909fda039aec54a1236e80f6a8abadea7662496bddbb42be6bfb2f17959d1f416e56c71b1931870262f5e801119242ca026bfc821e7e7daf2451138e645bb80c617669314e2fbe70de98ec76a9e40dad47f36fd9f7d0d42a4b5f1185ccdcf16ff46295d8a0fa17713c5802630933a9a34af674f3f39fe23491237c08822dec110911e893d0a8c4f677747abc360934b82910ff85bfd995083bba2987a67399eac427d145d546a40b9f6ff14ac488ec130fb3850a27af9544ae15a7e454dea05918b41243513f000000000000000a3621c56cea8d20fa911a0c41db6ebe8cac64f17679141d54b34bbc9963ac4f4bb3309603f1d4ab966203861b5b15a841f2b575a8bd0d78248ebe4d9a80002695104f674c2431dca141fae269cab70e9a66f3c3a9a63e9639e1f59c0ede26c6b5d74b078a5e15771aaa18119a867e1088334975e9f73483b6a62fa678ca14ffd9f9db2a7869d85864056526f889af43a6056080572286522449df466c632b3570243f989cce7cd9f465e41e610c20d80421d653a5520000008213b704c7fb082ff27590678ef9f190bae97909507041d860420c5664b27921b14dc1db8892fd32d0ad7bad8deff4b05f60cea0da7710ac0000000000008000bea37ce0d0d4aa202f928f28381aab144a5d429a04a6a2b83c7068ae949ed06e288e810bac9c76600025e19c907f8ea2e2010000008271a1f5f8528f227e79c1389dbdfffe492f21579d2c15b8c70cdb1c332d86d87341432750861ec2bc3451edca194b221cfec4603d276bbaa1dfa6d4fb8a48a76eafc9a9a0270e4c10d64cd5a62427264f2377fe763c43470833ac96c45f357cbbaba8f1b1fdcc7cbb61a7cdb9744ed7f9129aede2be21ccfdc4e9134f8684b3a4f354da9a795e96334e207dff70f1988037b2ed3aaf575c0b88d8f146684078416d59fdee5325928974d12dad99dac44c3f0008047096a44002bebc2420aed92fa9b6578b4779415d4ac01b75d5495c118045651cf41c2fc48b778efa5ea5677747430af4162b987b80c3e001cd34e5c92f76cc4c24eeb8bc4e9ac2aed9e53803ed0ca4ae3a9737d214060005ea6f1783e287b3bee96e3a726eafe2fdfaa78d1f48c13b64df07847754b8400daaa69bf5c8f4350aeae9ca1207e78283cd0b20ceb360c7e658828163e2d25c4aa348561f927e88f63aa70e73a5e69b3df3495903f06572e1e007fa55a2999f596d067312f5779e8dbfdcf3427138f3d444d2639a10477f9bec4b0bbb6e3c04be68981f392203dd0ee3ef478e16dacfc5e3e03cf7ab8e3902f1b0ff034ef655b253ca509383815b1b6fc6522d4e4fdc11a48cf42d48604675fde2b94cf00500a2690891abf8ab9c015073014d9e08d4338b8780bdecd436cf0541359bafffa45237f104b96210403b2de9efed496f42355bc7872c827467cfa5c4e72730d56bd068ed211cf847535edecb7b373f78b095b68441a34cb51682a8ae4d24ad0465f3927f889b813076038e79a7962fb385a882e8020f06c4c2ba1dd5cac7c18876da865d258734dd73583df292892448039ef799cf0630becdcce04579b5561dc825ab829827945e020c1f67ee615feb6243378e0610060f02cca4e91b2f001edb3d78fb4b55668dda93aec92a5de203717aa49c2d284acfabe262fccfcbb2b75a2183c46eb65ca8104e1b4da7fbb77ab2fc043aead87c32ab875ee7c2e7b7019c982cd3b43eaeb1a5fb135c0c7dcee8fe6516a328032f88c042891824659e9e94265c803b35ee5f83a2b210520106b8a358b50ab7a1fa89af9c251fe5294b3d1802d5676d95f160ec97b1ad94872cb2044642c37b4a6cc6c04effc1672db7e4b6080000007a508ae54b3cd7369dde50e8c77d95a3d361c040babb171607caac2a3559ad4f75465f49c0d0ae3716db6e00cb11db4a5fade2a57c10238e204a67737c3b42aae501b20f7694a00f16e2d0174035a2c22656dc29880acebdbe8ddbd75c2f998d8ac2dfad2ba3a504767b6b45a45957f24d758ed024b3849c11d412a2a03b4047497022d9c30e23ef4df5c89644f48bb536f7945b59d7bcddff754413d135273ea8e75f22f216c6b9990ae71806f2c00b4025c48b75c0f73cdb9a7b8fa367b50028067e7f16f4dd569d462f4f19eacdb3ed70eeebb4483f8fd777d443e8b40427db6fe29068c0ca3d2414442e8f3a154704b0e51bc664a137b26be719f4f7c9a5678a674dfc95df80b9ce375dd649c8c704e509bd88c8e63d8c7dd67071115c8982ba46af4d6adcc9f68a75b9397b035153faf46366e7205dd8d6f37525c1a0e94610dd94323f6c15d085197149bfd6655548cfd9c52c9711937f79abb1a124f1210465483cd3b2d78378cfb85ed82e7da0f6eb6d279f2ae455925d0f6f1ba571eba281f2a654fb39dd0000000039ff158e7c5419e037f3e3ad038f2211f1033195563c7f93cd54b9094f226e783271e1e5a2a2c10712eab625d64931cd4ffe6738d97b9b5ef828ee9fb06ffc01af0e79c1e14b1d25988c69a399567c1d93768f7971d31488b8658a20878b7c1dd7ba02fc42939dde3d4a3339a65d507dc59c51097b40517705da56e9ebf0afa53282bf86dbb58c548069ff6eb95aade7cc66d7bbef724779ca1f731b3346ff177050373d79ff7b3e7f9bc0c1b4b266a8878b90baaa039d3e3b63979ac3df6e6f4859afd50238c7547a39b60810938044ae185d2ba3e00a4e73676864ae090d81eaee5ee6cf1d0ab378dd4dd891e937c2ea5410e0513005000000000000003911fab964c271550027697b52160687461602f88df165d884b36ec2b6c25a2f33c715687e9d4afb96d6861aca47da73d6f3144345f48843dd014e5c5ad8fe995754bd9cf32fce1e31919c4b2082fb0a30b9deae84bed4b28045634073c9c58c89d9e99c81769177c6d594f88a4facfd4c735a20307c737afa2d60399473296b831dbd933d93994ba3064279b10ea0c5833f41f157ea2302993dbe433b1aa3a3766d5439020484f4113c4c859465c3b415c3432f81db8719539d5bf372aaaea1cc43a6c5cbe59758bfee2916580dac4b008e595f437491d87abed02cefcd9db53d94d02daee67918e5d6787463183b4b87c1050000002f7809959bc048850613d17ca51055f2f416a44fe180d2d50c312cca7cb14a2bdc331f57a9817139a206fc76957227ffff2de20a4b8e3737fbb42913777c06376f799eba367e21f94ca598705f5dcb767d6f0900d6b0f6095e53c4c4234d0c1fbe434f6ab8f43c0013ee93b83946ee7759e89d7bdd1a32d7b311711b757fe43c06d21a35810d8fe98b27faea8aa12bc8716eefc5c97c45ac33eeec964c5214bc3a9359bdea1cccab94f15e36319cb34ebcacedb82c2ed3de692839d7961939adfdeeeaff19d11efcafb6d546fef271e89d6cc2389e81ff58cefcce3fbf4625a7e7de40e42e07b34449e15e065cc7340002000000000000f288a4510de03dab19d26285eda89156d50dd385a60333ba5bbf5d77cd7007ad1519ad5470de3dd6d6080cafccf8a97406bb6b68a1f0c4549820a73c880f475f732ae00398e8bd1f4108b7807fb33b72685ec37a2d3f766413a60459516246e5a1d998a2017aef0948a68cf255315ab80dd349e891aef595dc4d470e8ac32a308e15fc37d06aeac289c0523f483e1ff7408c6087f1ab652f2ef91d4f2b01987b0f46da034e5c3f745a7ee8101a3934c54e24b48ec0275e2d0687dc746b0827cbf652f406c6b95f2722e58c05f752ce2126596e1cd7655b904801784c416b22f73d324678e2724f43f1fe687c7e8a60c28b82b6528341b648cdd56fed7cdcbb15da202d5ecd36dea3bca0b7427d8392c6289455e8f8d2ab2242729251ae033a9e02210e62df0546a74b333a1c48f95fd54acb5741259e8c5488efeee327415cc19451432c6f14c27693102a3cd84857cd6586fc5ca9a93eb0145fac0662ff86107f998a8ef7df8aa14046c55b03d3d47f88a8d60f7774a2ee08758897fb411a94b3c2fc5d5f0db42c0456ec015f08e5247d33ae2d35603ff8454c16f8342856935125102bb784ed7148b6ce431b63ee356b0c785f2f47b90e29389f22fc5b59a70efaea2bd40195af4486220d702e30bfc43c10ec23ea6283994a7dde4dcb61fea6b651fb1d62458d0741a12830052fcc460db043afe525629b40d7cee458e4cb5e930ed624806c43a006e39336d07c2b8081c128ad2706f48261f7897484c297a1a6613bc18f5a38d442768af38041efe03d152ef95ff569e76db2391f4509d7f339d92fdb4a89364949da398000000000000000d80a4fe654578376e599aff3565b1d531f30912b9945030b81ea9935fd46edb44a78f615255490a4b621501f2a9e4d24624c4dac9274118c67584f5d374755534d7f68f679c4ff516a9c861a0e7e65868fcb2bf1cb9aea4e05df72279fdb0d2b9e935c5af3cf474bed79dfc248c1f5aea4b8b32c5d295e57079d0fe662a46b7f71cd47744db86c50b704c971d90295c7b2c7439a2d78ccfa79b5fc2bff6bbf840262bf89394b3e0691953264d2700c838fa2c7b3425260f59554e502dcea39cb313b0000000000004ca7c12f45858d6284ca6270d6b2f0e58fded8a7b4a302a97bc641df07720ba2b26bbfcc807ca0abb1b44322269c21c5ec68cb068ea88067d905ea917bb03eefdaebdeabf2d0dce80997c915c8949de992587c2cb5fe36d7d3e5db21b094b8b77940b5f07722e47a08d367e5f84c96ec664b72934b99b3109af65d77e86abd6859cddf4bbae1f0930462df15fddbc48562ea3511a8065ef028cf12f14dcf6ebecd8d884836174faf1aa609e5f1ee1162dfa13bdc1fa7cfaadba85c72e9758f03a755d0be53f8d2a1dfb1c68cc164b0a0780d971a96ea2c4d4ca0398c2235980a9307b3d5bd3b01faffd0a5dbed2881a9700af561ac8c6b00000000000000f96f06817fb903729a7db6ff957697c9ede7885d94ffb0969be0daf60af93109eb1dee72e4363f51af62af6fb2a6df3bec89822a7a0b678058fa3fef86faec216eb6992162f8dcbf719c148cd2f9c55f4901203a9a8a2c3e90f3943dbc10360a1a49700d1dfbf66d69f6fbaf506c8bcce8bb0d877a4eddd5d0fc5a752f9000", 0x1025}}, 0x1006)

executing program 2:
syz_mount_image$ext4(&(0x7f0000000040)='ext4\x00', &(0x7f0000000080)='./file1\x00', 0x20081e, &(0x7f00000020c0), 0x1, 0x4ef, &(0x7f0000000a00)="$eJzs3U1vW1kZAODXzpeTyUwywywAAVOGgYKqOonbRlUXUFYIoUqILkFqQ+JGUew4ip3ShC7S/4BEJVaw5Aew7oo9GwQ7NmWBxEcEaiqxMLrXN6mb2k1oEjuKn0e6uvfcY/s9J849x36d+AQwsC5FxE5EjEbE/YiYys7nsi1ut7bkdi92Hy/u7T5ezEWzefefubQ+ORdt90m8lz1mISJ+9L2In+bejFvf2l5dqFTKG63i+Eyjuj5T39q+ulJdWC4vl9dKpfm5+dmb126UTq2vn1RHs6MvP//Dzrd+njRrMjvT3o/T1Or6yEGcxHBE/OAsgvXBUNaf0X43hHeSj4iPIuLT9PqfiqH02QQALrJmcyqaU+1lAOCiy6c5sFy+mOUCJiOfLxZbObyPYyJfqdUbVx7UNteWWrmy6RjJP1iplGezXOF0jOSS8lx6/KpcOlS+FhEfRsQvxsbTcnGxVlnq5wsfABhg7x2a//8z1pr/AYALrtDvBgAAPWf+B4DBY/4HgMFj/geAwWP+B4DBY/4HgMFj/geAgfLDO3eSrbmXff/10sOtzdXaw6tL5fpqsbq5WFysbawXl2u15fQ7e6pHPV6lVlufux6bj6a/vV5vzNS3tu9Va5trjXvp93rfK4/0pFcAwNt8+MmzP+ciYufWeLpF21oO5mq42PL9bgDQN0P9bgDQN1b7gsF1gvf40gNwQXRYovc1hYgYP3yy2Ww2z65JwBm7/AX5fxhUbfl/fwUMA0b+HwaX/D8MrmYzd9w1/+O4NwQAzjc5fqDL5/8fZfvfZh8O/GTp8C2enmWrAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4HzbX/+3mK0FPhn5fLEY8X5ETMdI7sFKpTwbER9ExJ/GRsaS8lyf2wwAnFT+b7ls/a/LU59NHq4dzb0cS/cR8bNf3f3lo4VGY+OPyfl/HZxvPM3Ol/rRfgDgKPvzdLpveyP/Yvfx4v7Wy/b8/bsRUWjF39sdjb2D+MMxnO4LMRIRE//OZeWWXFvu4iR2nkTE5zv1PxeTaQ6ktfLp4fhJ7Pd7Gj//Wvx8WtfaJz+Lz51CW2DQPEvGn9udrr98XEr3na//QjpCnVw2/iUPtbiXjoGv4u+Pf0Ndxr9Lx41x/fffbx2Nv1n3JOKLwxH7sffaxp/9+Lku8T87Zvy/fOkrn3ara/464nJ0jt8ea6ZRXZ+pb21fXakuLJeXy2ul0vzc/OzNazdKM2mOeqb7bPCPW1c+6FaX9H+iS/zCEf3/+jH7/5v/3v/xV98S/5tf6xQ/Hx+/JX4yJ37jmPEXJn5X6FaXxF/q0v+jnv8rx4z//K/bbywbDgD0T31re3WhUilv9PJg/4VET4M6uAAHyW/NOWhGx4Pv9CrWaPxf92o23ylWtxHjNLJuwHlwcNFHxMt+NwYAAAAAAAAAAAAAAOioF/+x1O8+AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcHH9LwAA//89fM7W")
setxattr$trusted_overlay_upper(&(0x7f0000000200)='./file1\x00', &(0x7f00000001c0), &(0x7f0000001400)=ANY=[], 0x835, 0x0)
unlink(&(0x7f0000000100)='./file1\x00')

executing program 4:
syz_mount_image$ext4(&(0x7f0000000040)='ext4\x00', &(0x7f0000000080)='./file1\x00', 0x20081e, &(0x7f00000020c0), 0x1, 0x4ef, &(0x7f0000000a00)="$eJzs3U1vW1kZAODXzpeTyUwywywAAVOGgYKqOonbRlUXUFYIoUqILkFqQ+JGUew4ip3ShC7S/4BEJVaw5Aew7oo9GwQ7NmWBxEcEaiqxMLrXN6mb2k1oEjuKn0e6uvfcY/s9J849x36d+AQwsC5FxE5EjEbE/YiYys7nsi1ut7bkdi92Hy/u7T5ezEWzefefubQ+ORdt90m8lz1mISJ+9L2In+bejFvf2l5dqFTKG63i+Eyjuj5T39q+ulJdWC4vl9dKpfm5+dmb126UTq2vn1RHs6MvP//Dzrd+njRrMjvT3o/T1Or6yEGcxHBE/OAsgvXBUNaf0X43hHeSj4iPIuLT9PqfiqH02QQALrJmcyqaU+1lAOCiy6c5sFy+mOUCJiOfLxZbObyPYyJfqdUbVx7UNteWWrmy6RjJP1iplGezXOF0jOSS8lx6/KpcOlS+FhEfRsQvxsbTcnGxVlnq5wsfABhg7x2a//8z1pr/AYALrtDvBgAAPWf+B4DBY/4HgMFj/geAwWP+B4DBY/4HgMFj/geAgfLDO3eSrbmXff/10sOtzdXaw6tL5fpqsbq5WFysbawXl2u15fQ7e6pHPV6lVlufux6bj6a/vV5vzNS3tu9Va5trjXvp93rfK4/0pFcAwNt8+MmzP+ciYufWeLpF21oO5mq42PL9bgDQN0P9bgDQN1b7gsF1gvf40gNwQXRYovc1hYgYP3yy2Ww2z65JwBm7/AX5fxhUbfl/fwUMA0b+HwaX/D8MrmYzd9w1/+O4NwQAzjc5fqDL5/8fZfvfZh8O/GTp8C2enmWrAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4HzbX/+3mK0FPhn5fLEY8X5ETMdI7sFKpTwbER9ExJ/GRsaS8lyf2wwAnFT+b7ls/a/LU59NHq4dzb0cS/cR8bNf3f3lo4VGY+OPyfl/HZxvPM3Ol/rRfgDgKPvzdLpveyP/Yvfx4v7Wy/b8/bsRUWjF39sdjb2D+MMxnO4LMRIRE//OZeWWXFvu4iR2nkTE5zv1PxeTaQ6ktfLp4fhJ7Pd7Gj//Wvx8WtfaJz+Lz51CW2DQPEvGn9udrr98XEr3na//QjpCnVw2/iUPtbiXjoGv4u+Pf0Ndxr9Lx41x/fffbx2Nv1n3JOKLwxH7sffaxp/9+Lku8T87Zvy/fOkrn3ara/464nJ0jt8ea6ZRXZ+pb21fXakuLJeXy2ul0vzc/OzNazdKM2mOeqb7bPCPW1c+6FaX9H+iS/zCEf3/+jH7/5v/3v/xV98S/5tf6xQ/Hx+/JX4yJ37jmPEXJn5X6FaXxF/q0v+jnv8rx4z//K/bbywbDgD0T31re3WhUilv9PJg/4VET4M6uAAHyW/NOWhGx4Pv9CrWaPxf92o23ylWtxHjNLJuwHlwcNFHxMt+NwYAAAAAAAAAAAAAAOioF/+x1O8+AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcHH9LwAA//89fM7W")
setxattr$trusted_overlay_upper(&(0x7f0000000200)='./file1\x00', &(0x7f00000001c0), &(0x7f0000001400)=ANY=[], 0x835, 0x0)
unlink(&(0x7f0000000100)='./file1\x00')

[  634.601415][T16296] loop1: detected capacity change from 0 to 64
[  634.607243][T14884] XFS (loop2): Unmounting Filesystem bfdc47fc-10d8-4eed-a562-11a831b3f791
[  634.622261][T16170] netdevsim netdevsim0 netdevsim0: renamed from eth0
[  634.733709][T16170] netdevsim netdevsim0 netdevsim1: renamed from eth1
[  634.784379][T16170] netdevsim netdevsim0 netdevsim2: renamed from eth2
[  634.789975][T16299] loop4: detected capacity change from 0 to 512
executing program 1:
bpf$MAP_CREATE(0x0, &(0x7f0000000000), 0x48)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f0000000040)={&(0x7f0000000000)='ext4_ext_show_extent\x00'}, 0x10)
r0 = openat$kvm(0xffffffffffffff9c, &(0x7f0000000040), 0x0, 0x0)
r1 = ioctl$KVM_CREATE_VM(r0, 0xae01, 0x0)
r2 = openat$cgroup_ro(0xffffffffffffff9c, &(0x7f00000001c0)='blkio.bfq.io_wait_time_recursive\x00', 0x275a, 0x0)
write$binfmt_script(r2, &(0x7f0000000000), 0x208e24b)
mmap(&(0x7f0000000000/0xb36000)=nil, 0xb36000, 0x2, 0x28011, r2, 0x0)
preadv(r2, &(0x7f00000015c0)=[{&(0x7f0000000080)=""/124, 0xffffff23}], 0x1, 0x0, 0x0)
ioctl$KVM_SET_USER_MEMORY_REGION(r1, 0x4020ae46, &(0x7f0000000400)={0x0, 0x0, 0x0, 0x20002000, &(0x7f0000000000/0x2000)=nil})
r3 = ioctl$KVM_CREATE_VCPU(r1, 0xae41, 0x0)
syz_kvm_setup_cpu$x86(0xffffffffffffffff, r3, &(0x7f0000000000/0x18000)=nil, &(0x7f0000000140)=[@text64={0x40, 0x0}], 0x1, 0x64, 0x0, 0x0)
sendmsg$NL80211_CMD_SET_REKEY_OFFLOAD(0xffffffffffffffff, &(0x7f0000000300)={0x0, 0x0, 0x0}, 0x0)
ioctl$KVM_RUN(r3, 0xae80, 0x0)

executing program 3:
syz_mount_image$ext4(&(0x7f0000000440)='ext4\x00', &(0x7f0000000480)='./file0\x00', 0x248, &(0x7f0000000000), 0xfd, 0x48d, &(0x7f0000000940)="$eJzs3M1rHOUfAPDvzG6SX1+TX60vrdVGq1h8SZq0akHBFxA8KAh6qCeJSVpq00aaCLYEG6XUi6AF7yJ4EfwLPHkS9SR41bsUivTS6mllMrPrJtnNSzfJptnPByY7z+7MPt/vzDwzz8zsJICO1Z/9SSJ2RsTvEdEbEenCCbblL7duzIz+fWNmNIlK5c2/kmy2uHljZrQ6aVK87sgL5eyL0stJvNig3qkLF8+MTEyMny/Kg9Nn3x+cunDxqdNnR06Nnxo/N3z8+LGjQ88+M/z0muSZxXRz/0eTB/a9+vbV10dPXH335++SuqDr82jRc7210ZnaMlno0TWqbLPYVTeelNsYCKvSExHZ6uqaa/+9Ubq8u/ZZb7zySVuDA9ZVpVKpDDf/eLYCbGFJtDsCoD2qB/rs/Lc6bFDXY1O4/lJ+ApTlfasY8k/K+XWQnvzcaNc61d8fESdm//kqG2LV1yG61ikqAGAr+yHr/zzZoP9Xjrinbrrdxb2hvoj4f0TsiYi7ImJvRNwd+bT3RsR9javpf6dJ/f0Lyov7P+m1FtJbVtb/e764tzW//1e7C9ZXKkq75vLvSk6enhg/UiyTw9HVk5WHGn57EjGbvf72ebP66/t/2ZDVX+0LFnFcK/fMn2dsZHqk5cQL1z+O2F9ulH8S5f+yiH0Rsf826zj9+LcH5r9Tqo0tn/8S1uA+U+XriMfy9T8bC/KvSpa+Pzn4v5gYPzJY3SoW++XXK280qz/PP42l89/WeqJNZOt/e6Pt/4Va/n1J/f3aqUVf0b1cHVf++LTpOc3tbv/dyVvzKv9wZHr6/FBEd/La4vfrLnBXy9Xps/wPH2rc/vcU82T53x8R2Ub8QEQ8GBEHi9gfioiHI+LQEvn/9PIj7zXN/2AL2/8ayPIfa7j/a7b+Vz9SOvPj983qX9n6P1YtzAW1kv3fSgNsZdkBAADAnSKNiJ2RpAO18TQdGMh/L783tqcTk1PTT5yc/ODcWP6MQF90pdUrXb1110OHimvD1fJwUb5UlI8W142/LG2bKw+MTk6MtTt56HA7mrT/zJ+ldkcHrDvPa0Hn0v6hc91++7fngDvdMq043ag4gI3nKA6dq1H7v1RfSCL/lTyw5Tj+Q+eqtf8vVjBx3eNeCx/eBO48Sx3/K70bGAiw4fT/oSO18lz/phiJbyKWnibZLKGuauSzVmYvb0CEkbZx+XS3ZaUMlyLauEmUV/pfLeJC5VLLlbZ7zwQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALA2/g0AAP//oVvkeQ==")
mount$tmpfs(0x0, &(0x7f0000000080)='./file0/../file0\x00', &(0x7f00000000c0), 0x0, 0x0)
lsetxattr$system_posix_acl(&(0x7f0000000000)='./file0\x00', &(0x7f0000000180)='system.posix_acl_default\x00', &(0x7f0000000380)=ANY=[@ANYBLOB="0200000001000000000000000400000000000000100000000000000020"], 0x24, 0x0)
llistxattr(&(0x7f0000000280)='./file0\x00', 0x0, 0x2)

[  634.885361][T16170] netdevsim netdevsim0 netdevsim3: renamed from eth3
[  634.895286][T16299] EXT4-fs (loop4): mounted filesystem 00000000-0000-0000-0000-000000000000 r/w without journal. Quota mode: writeback.
[  634.997042][T16299] ext4 filesystem being mounted at /root/syzkaller-testdir3208322292/syzkaller.v3fGEZ/19/file1 supports timestamps until 2038-01-19 (0x7fffffff)
[  635.228225][T16170] 8021q: adding VLAN 0 to HW filter on device bond0
[  635.361258][T16170] 8021q: adding VLAN 0 to HW filter on device team0
[  635.367670][T16311] loop2: detected capacity change from 0 to 512
[  635.426538][  T927] bridge0: port 1(bridge_slave_0) entered blocking state
[  635.433751][  T927] bridge0: port 1(bridge_slave_0) entered forwarding state
executing program 3:
r0 = bpf$BPF_PROG_RAW_TRACEPOINT_LOAD(0x5, &(0x7f0000000240)={0x11, 0x3, &(0x7f0000000040)=@framed, &(0x7f0000000000)='GPL\x00'}, 0x90)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f0000000200)={&(0x7f00000004c0)='contention_begin\x00', r0}, 0x10)
r1 = syz_init_net_socket$nl_generic(0x10, 0x3, 0x10)
r2 = syz_genetlink_get_family_id$nl802154(&(0x7f0000000dc0), 0xffffffffffffffff)
sendmsg$NL802154_CMD_DEL_SEC_LEVEL(r1, &(0x7f0000000f00)={0x0, 0x0, &(0x7f0000000ec0)={&(0x7f0000000e00)={0x14, r2, 0x1, 0x0, 0x0, {0x26}}, 0x14}}, 0x0)

[  635.497774][  T927] bridge0: port 2(bridge_slave_1) entered blocking state
[  635.504990][  T927] bridge0: port 2(bridge_slave_1) entered forwarding state
[  635.522756][T16311] EXT4-fs (loop2): mounted filesystem 00000000-0000-0000-0000-000000000000 r/w without journal. Quota mode: writeback.
[  635.535776][T16311] ext4 filesystem being mounted at /root/syzkaller-testdir440857763/syzkaller.Ihi0LS/94/file1 supports timestamps until 2038-01-19 (0x7fffffff)
executing program 4:
socket(0x10, 0x803, 0x0)
r0 = socket$netlink(0x10, 0x3, 0x0)
socketpair$unix(0x1, 0x5, 0x0, &(0x7f00000000c0)={0xffffffffffffffff, <r1=>0xffffffffffffffff})
r2 = dup(r1)
getsockname$packet(r2, &(0x7f00000000c0)={0x11, 0x0, <r3=>0x0, 0x1, 0x0, 0x6, @random}, &(0x7f0000000140)=0x14)
sendmsg$nl_route(r0, &(0x7f0000000080)={0x0, 0x0, &(0x7f0000000040)={&(0x7f0000000500)=@newlink={0xec, 0x10, 0x801, 0x0, 0x0, {0x0, 0x0, 0x0, r3}, [@IFLA_AF_SPEC={0xcc, 0x1a, 0x0, 0x1, [@AF_INET6={0x18, 0x2, 0x0, 0x1, [@IFLA_INET6_TOKEN={0x14, 0x7, @local}]}, @AF_INET={0x30, 0x2, 0x0, 0x1, {0x4, 0x1, 0x0, 0x1, [{0x3}, {0x8}, {0x4}, {0x8}, {0x8}]}}, @AF_INET={0x18, 0x2, 0x0, 0x1, {0x14, 0x1, 0x0, 0x1, [{0x11}, {0x8}]}}, @AF_INET6={0x18, 0xa, 0x0, 0x1, [@IFLA_INET6_TOKEN={0x14, 0x7, @mcast2}, @IFLA_INET6_TOKEN={0x0, 0x7, @mcast2}, @IFLA_INET6_TOKEN={0x0, 0x7, @dev}]}, @AF_INET={0x28, 0x2, 0x0, 0x1, {0x24, 0x1, 0x0, 0x1, [{0x8}, {0x8}, {0x8}, {0x8}]}}, @AF_MPLS={0x4}, @AF_INET6={0x0, 0xa, 0x0, 0x1, [@IFLA_INET6_TOKEN={0x0, 0x7, @rand_addr=' \x01\x00'}, @IFLA_INET6_ADDR_GEN_MODE, @IFLA_INET6_ADDR_GEN_MODE, @IFLA_INET6_TOKEN={0x0, 0x7, @dev}, @IFLA_INET6_TOKEN={0x0, 0x7, @mcast2}, @IFLA_INET6_TOKEN={0x0, 0x7, @rand_addr=' \x01\x00'}, @IFLA_INET6_TOKEN={0x0, 0x7, @private1}, @IFLA_INET6_ADDR_GEN_MODE, @IFLA_INET6_ADDR_GEN_MODE]}, @AF_MPLS={0x4}]}]}, 0xec}}, 0x0)

[  635.616544][T15853] EXT4-fs (loop4): unmounting filesystem 00000000-0000-0000-0000-000000000000.
executing program 1:
r0 = open(&(0x7f0000000180)='./bus\x00', 0x14927e, 0x0)
r1 = creat(&(0x7f0000000000)='./bus\x00', 0x0)
write$binfmt_elf32(r1, &(0x7f0000000240)={{0x7f, 0x45, 0x4c, 0x46, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x38}, [{}]}, 0x58)
mmap(&(0x7f0000000000/0x600000)=nil, 0x600000, 0x27fffff, 0x4002011, r0, 0x0)
fallocate(r0, 0x0, 0x0, 0x1000f4)
modify_ldt$write(0x1, &(0x7f0000000200), 0x10)
modify_ldt$read(0x0, &(0x7f0000001880)=""/4096, 0x1000)

[  635.795811][T14884] EXT4-fs (loop2): unmounting filesystem 00000000-0000-0000-0000-000000000000.
[  635.876117][ T5093] Bluetooth: hci2: command tx timeout
executing program 2:
open(&(0x7f0000000100)='./bus\x00', 0x143142, 0x0)
r0 = open(&(0x7f0000000040)='./bus\x00', 0x10103e, 0x0)
mmap(&(0x7f0000000000/0x600000)=nil, 0x600000, 0x7ffffe, 0x4002011, r0, 0x0)
ftruncate(r0, 0x20cf01)
open(&(0x7f00000001c0)='./file1\x00', 0x1cd27e, 0x0)
open(&(0x7f0000000180)='./bus\x00', 0x14927e, 0x0)
write$FUSE_STATFS(0xffffffffffffffff, &(0x7f00000000c0)={0x60}, 0x60)

executing program 1:
r0 = syz_open_dev$video(&(0x7f0000000000), 0x0, 0x0)
ioctl$VIDIOC_QUERYBUF_DMABUF(r0, 0xc0585609, &(0x7f0000000080)={0x0, 0x7, 0x4, 0x0, 0x0, {0x0, 0x2710}, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, "5196856d"}})

[  636.132518][T16322] A link change request failed with some changes committed already. Interface ip_vti0 may have been left with an inconsistent configuration, please check.
executing program 3:
bpf$PROG_LOAD(0x5, &(0x7f00002a0fb8)={0x0, 0x4, &(0x7f00000004c0)=ANY=[@ANYBLOB="8500000007000000350000000000000085000000a000000095000000000000001b90b31a08f54ff40571eda5c56ad924a10c7b1e6003c9325fea577f8e56fe212b358f1d0838c8119ed74e74552ce4e2c8093375e35c8250f448a6a31260c2f9fbb70400000000000000b08b7aab5fd5d24dcff1ca14025b73c2da8f550900000000000000c340b111fcee90d6d90100000001000000babdee5b76635ce4f35f985e434196b5699ba66b9cb05e5259a1f61cafa3586a2228c4581dc2"], 0x0}, 0x90)
r0 = socket$nl_generic(0x10, 0x3, 0x10)
r1 = syz_genetlink_get_family_id$nl80211(&(0x7f0000000640), 0xffffffffffffffff)
r2 = socket$nl_netfilter(0x10, 0x3, 0xc)
getsockopt$inet_sctp6_SCTP_GET_PEER_ADDRS(0xffffffffffffffff, 0x84, 0x6c, &(0x7f00000005c0)={0x0, 0x78, "f3dcd9c3b134ea5dc4c0d086b0739a6d06f184e5fb193a8e68e02074c8e2f3a5f07d66c89afc9d57170f51ee968e63fa0bb85d3dfb0c13ebeda4908b55f15550cffdee42aa94d7992cddca9da43375c0482f5ae89db1a0a70afd7a913ad17e55637d145e3af9056ab902f54daff812a0c9f3b0a38a2e7e2d"}, 0x0)
ioctl$sock_SIOCGIFINDEX_80211(r2, 0x8933, &(0x7f0000000340)={'wlan1\x00', <r3=>0x0})
bpf$PROG_LOAD(0x5, &(0x7f0000000040)={0x0, 0x4, &(0x7f0000000680)=ANY=[@ANYBLOB="180200000400000000000000000000008500f5003600000095000000000000000a8cd378b09e7ffa318d9cc23d42836e0abe28a8e781a2c6ec1edbcce3f930bbd728eb5fddb992b077efbd59ef8b231db9d195af709ec038c0db020924fcc070636479703cdf8f58bb2abf7c"], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
sendmsg$NL80211_CMD_FRAME(r0, &(0x7f0000000440)={0x0, 0x0, &(0x7f0000000400)={&(0x7f0000000480)=ANY=[@ANYBLOB="98030000", @ANYRES16=r1, @ANYBLOB="010028057000fcdbdf253b00000008000300", @ANYRES32=r3, @ANYBLOB="04008e00080057001b0a000004006c000500190107000000080026006c0900005603330080b0c000ffffffffffff0802110000010569ea7fa08e8df3d0edd086922799ded6be01d09a95b66d3d90"], 0x398}}, 0x0)

executing program 4:
syz_open_dev$evdev(0x0, 0x0, 0x0)
r0 = bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x11, 0xb, &(0x7f0000000180)=ANY=[@ANYBLOB="18000000000000000000000000000000180100002020702500000000002020207b1af8ff00000000bfa100000000000007010000f8ffffffb702000002000000b7030000e8ffffff850000000400000095"], &(0x7f0000000040)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f00000000c0)={&(0x7f0000000080)='sched_switch\x00', r0}, 0x10)
prlimit64(0x0, 0xe, &(0x7f0000000140)={0x8, 0x8b}, 0x0)
sched_setscheduler(0x0, 0x1, &(0x7f0000000080)=0x7)
r1 = getpid()
sched_setscheduler(r1, 0x2, &(0x7f0000000200)=0x4)
mmap(&(0x7f0000000000/0xb36000)=nil, 0xb36000, 0xb635773f06ebbeee, 0x8031, 0xffffffffffffffff, 0x0)
socketpair$unix(0x1, 0x2, 0x0, &(0x7f0000000200)={<r2=>0xffffffffffffffff, <r3=>0xffffffffffffffff})
connect$unix(r2, &(0x7f000057eff8)=@abs, 0x6e)
sendmmsg$unix(r3, &(0x7f00000bd000), 0x318, 0x0)
recvmmsg(r2, &(0x7f00000000c0), 0x10106, 0x2, 0x0)
r4 = socket$inet6_sctp(0xa, 0x1, 0x84)
creat(&(0x7f00000001c0)='./file0\x00', 0x0)
sendto$inet6(r4, &(0x7f0000000300)="8b", 0x34000, 0x0, &(0x7f0000000000)={0xa, 0x0, 0x0, @private1}, 0x1c)
shutdown(r4, 0x1)

executing program 1:
syz_mount_image$exfat(&(0x7f00000000c0), &(0x7f0000000000)='./file0\x00', 0x800, &(0x7f0000000200)={[{@iocharset={'iocharset', 0x3d, 'maciceland'}}, {@gid}, {@gid}, {@errors_continue}, {@iocharset={'iocharset', 0x3d, 'iso8859-2'}}, {@umask={'umask', 0x3d, 0x4}}, {@fmask={'fmask', 0x3d, 0x6}}, {@errors_remount}, {@utf8}, {@errors_continue}]}, 0x1, 0x152d, &(0x7f0000001f80)="$eJzs3AuYTtUaOPD3XWvtMSS+JrkMa6138yWXZZIklyS5JEklSXJLSJrkSEJiCEkakpBchiSGkFwmJo37/X5JSJImSXLLLVn/Z8Lf6dT5dy79j/OceX/Psx/rtfZa+93f+13W3jPzfddlSK3Gtas3JCL4t+CFf5IAIBYABgBAXgAIAKB8XPm4rP6cEpP+vYOwP9dDqVc6A3Ylcf2zN65/9sb1z964/tkb1z974/pnb1z/7I3rz1h2tnFqoWt4y74b3//Pzvjz/39IZpkxX60uc11XgJh/dAjXP3vj+v/PCv6Rnbj+2RvXP7uKvdIJsP8C/PrPDnL83R6uf/bG9WcsO7vS95+v9AaR/7LH4HDOC4X5T50/Y4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDH2H3DaX6YA4FL7SufFGGOMMcYYY4yxP4/PcaUzYIwxxhhjjDHG2P9/CAIkKAggBnJALOSEXCAA4GrIA3khAtdAHFwL+eA6yA8FoCAUgngoDEVAgwELBCEUhWIQheuhONwAJaAklILS4KAMJMCNUBZugnJwM5SHW6AC3AoVoRJUhipwG1SF26Ea3AHV4U6oATWhFtSGu6AO3A114R6oB/dCfbgP7ocHoAE8CA3hIWgED0NjeASawKPQFJpBc2gBLf+l8S9AD3gRekIvSILe0Adegr7QD/rDyzAAXoGB8CoMgtcgGQbDEHgdhsIbMAzehOEwAkbCWzAK3obRMAbGwjhIgfEwAd6BifAuTIL3YDJMgVSYCtPgfZgOM2AmfACz4EOYDXNgLsyDNPgI5sMCSIePYSF8AhmwCBbDElgKy2A5rICVsApWwxpYC+tgPWyAjbAJNsMW2ArbYDt8CjvgM9gJu2A3fA574It/cvypvxnfFQEBBQpUqDAGYzAWYzEX5sLcmBvzYB6MYATjMA7zYT7Mj/mxIBbEeIzHIlgEDRokJCyKRTGKUSyOxbEElsBSWAodOkzABCyLN2E5LIflsTxWwApYESthJayCVbAqVsVqWA2rY3WsgTWwFtbCu/Au7I11sS7Ww3pYH+tfuj2FDbEhNsJG2BgbYxNsgk2xKTbH5tgSW2IrbIWtsTW2xbbYDtthe2yPiZiIHbADdsSO2Ak7YWfsjF2wC3bFbtgt84UcgC/ii9gLa4je2Af7YF9MztEfX8aX8RUciK/iq/gaJuNgHIKv4+v4Bg7DkzgcR+BIHIlVxds4GscgiXGYgik4ASfgRJyIWYm+h1MwFafiNJyG03EGzsAPcBZ+iB/iHJyD8zAN03A+LsB0TMeFeAozcBEuxiW4FJfhUlyBK3EFrsY1uBrX4TrcgBtwE27CLbgFt+E2/BQVAH6Gu3AXJuMe3IN7cS/uw324H/djJmbiATyAB/EgHsJDeBgP4xE8isfwKJ7AE3gST+FpPI1n8Syew+fiv2n0aclVySCyKKFEjIgRsSJW5BK5RG6RW+QReURERESciBP5RD6RX+QXBUVBES/iRRFRRBhhBIkwBgBEVERFcVFclBAlRClRSjjhRIJIEGVFWVFOlBPlxS2igrhVVBSVRBtXRVQRVUVbV03cIaqL6qKGqClqidqitqgj6oi6oq6oJ+qJ+qK+uF88IBqI3tgfHxJZlWksBmMTMQSbimZCXnwHayWGYWvRRrQVT4gROBzbi1YuUTwtOojR2FH8RYzBZ0VnMQ67iOdFV9FNdBcviB6itespeolJ2Fv0EVOwr+gn+ouXxXSsKT7AWTlriddEshgshojXxTx8QwwTb4rhYoQYKd4So8TbYrQYI8aKcSJFjBcTxDtionhXTBLvicliikgVU8U08b6YLmaImeIDMUt8KGaLOWKumCfSxEdivlgg0sXHYqH4RGSIRWKxWCKWimViuVghVopVYrVYI9aKdWK92CA2ik1is4iFrWKb2C4+FTvEZ2Kn2CV2i8/FHvGF2Cu+FPvEV2K/+Fpkim/EAfGtOCi+E4fE9+Kw+EEcEUfFMXFcnBA/ipPilDgtzoiz4idxTvwszgsvQKIUUkolAxkjc8hYmVPmklfJ3DK4+OheI+PktTKfvE7mlwVkQVlIxsvCsojU0kgrSYayqCwmo/J6WVzeIEvIkrKULC2dLCMT5I2yrLxJlpM3y/LyFllB3iorykqysqwib5NV5e0SIheOUUPWlLVkbXmXTIK7ZV15j6wn75X15X3yfvmAbCAflA3lQ7KRfFg2lo/IJvJR2VQ2k81lC9lSPiZbycdla9lGtpVPyHbySdlePiUT5dOyg/QXnyLPys7yOdlFPi+7ym6yu/xZnpde9pS9JPQG2Ue+JPvKfrJ/LADIV+RA+aocJF+TyXKwHCJfl0PlG3KYfFMOlyPkSPmWHCXflqPlGDlWjpMpcrycIN+RE+W7cpJ8T06WU2SqnCr7ywG/zDRTyj8c/87vjB/0y9E3yI1yk9wst8itcpvcLj+VO+QOuVPulLvlbrlH7pF75V65T+6T++V+mSkz5QF5QB6UB+UheUgeloflEXlUnpHH5Qn5ozwpT8lT8ow8K8/KcxcfA1CohJJKqUDFqBwqVuVUudRVKre6WuVReVVEXaPi1LUqn7pO5VcFVEFVSMWrwqqI0sooq0iFqqgqpqLqerz4hFGlVGnlVBmVoG78Z8ar4uoGVUKV/NX4S/kl/Z38WqqWqpVqpVqr1qqtaqvaqXaqvWqvElWi6qA6qI6qo+qkOqnOqrPqorqorqqr6q66qx6qh+qpeqoklaT6qJdUX9VP9VcvqwHqFTVQDVSD1CCVrJLVEDVEDVVD1TA1TA1Xw9VINVKNUqPUaDVajVVjVYpKURPUBDVRTVST1CQ1WU1WqSpVTVPT1HQ1Xc1UM9UsNUvNVrPVXDVXpak0NV/NV+kqXS1UC1WGWqQWqSVqiVqmlqkVaoVapVapNWqNWqfWqQy1UW1Um9VmtVVtVdvVdrVD7VA7xU61W+1We9QetVftVfvUPrVf7VeZKlMdUAfUQXVQHVKH1GF1WB1RR9QxdUydUCfUSXVSnVan1Vl1Vp1T59R5dT5r2ReIQAQqUEFMEBPEBrFBriBXkDvIHeQJ8gSRIBLEBXFBvuC6IH9QICgYFArig8JBkUAHJrCBuFj0aHB9UDy4ISgRlAxKBaUDF5QJEoIbg7LBTUG54OagfHBLUCG4NagYVAoqB1WC24Kqwe1BteCOoHpwZ1AjqBnUCmoHdwV1gruDusE9Qb3g3qB+cF9wf/BA0CB4MGgYPBQ0Ch4OGgePBE2CR4OmQbOgedAiaPmnzu/9yQKPu566l07SvXUf/ZLuq/vp/vplPUC/ogfqV/Ug/ZpO1oP1EP26Hqrf0MP0m3q4HqFH6rf0KP22Hq3H6LF6nE7R4/UE/Y6eqN/Vk/R7erKeolP1VD1Nv6+n6xl6pv5Az9If6tl6jp6r5+k0/ZGerxfodP2xXqg/0Rl6kV6sl+ileplerlfolXqVXq3X6LV6nV6vN+iNepPerLforXqb3q4/1Tv0Z3qn3qV368/1Hv2F3qu/1Pv0V3q//lpn6m/0Af2tPqi/04f09/qw/kEf0Uf1MX1cn9A/6pP6lD6tz+iz+id9Tv+sz2uftbjP+ng3yigTY2JMrIk1uUwuk9vkNnlMHhMxERNn4kw+k8/kN/lNQVPQxJt4U8QUMVnIkClqipqoiZriprgpYUqYUqaUccaZBJNgypqyppwpZ8qb8qaCqWAqmoqmsqlsbjO3mdvN7eYOc4e509xpapqaprapbeqYOqauqWvqmXqmvqlv7jf3mwamgWloGppGppFpbBqbJqaJaWqamuamuWlpWppWppVpbVqbtqataWfamfamvUk0iaaD6WA6mo6mk+lkOpvOpovpYrqarqa76W56mB6mp+lpkkyS6WP6mL6mr+lv+psBZoAZaAaaQWaQSTbJZogZYoaaoWaYGWaGmxFmZNZC1bxtRpsxZqwZZ1JMiplgJpiJZqKZZCaZyWaySTWpZpqZZqab6WammWlmmVlmtplt5pq5Js2kmflmvkk36WahWWgyTIZZbBabpWapWW6Wm5VmpVltVpu1sNasN+vNRrPRbDabzVaz1Ww3280Os8PsNDvNbrPb7DF7zF6z1+wz+8x+s99kmkxzwBwwB81Bc8gcMofNYXPEHDHHzDFzwpwwJ81Jc9qcNmdNgYufl97E2pw2l73K5rZX2zw2r/3buKAtZONtYVvEapvfFvhVbKy1JWxJW8qWts6WsQn2xt/EFW0lW9lWsbfZqvZ2W+03cR17t61r77H17L22tr3rV3F9e5/NWp00QASwzWwj28I2to/YJvZR29Q2s81tC9vOPmnb26dson3adrDP/CaebxfYlXaVXW3X2J12lz1tz9iD9jt71v5ke9pedoB9xQ60r9pB9jWbbAf/Jh5p37Kj7Nt2tB1jx9pxv4kn2yk21U610+z7drqd8Zs4zX5kZ9l0O9vOsXPtvF/irJzS7cd2of3EZtgAFtsldqldZpfbFZdy9XntOrvebrA77Gd2s91it9ptdvulhbDdZXfbz+0e+4U9YL+1++xXdr89ZDPtN7/EWed3yH5vD9sf7BF71B6zx+0J+6O6NDrr3I/bn+156y0QEpAkRQHFUA6KpZyUi66i3HQ15aG8FKFrKI6upXx0HeWnAlSQClE8FaYipMmQJaKQilIxitL1dCm9UlSaHJWhBLqRytJNVI5upvJ0C1WgW6kiVaLKVIVuo6p0O1WjO6g63Uk1qCbVotp0F9Whu6ku3UP16F6qT/fR/fQANaAHqSE9RI3oYWpMj1ATepSaUjNqTi2oJT1Grehxak1tqC09Qe3oSWpPT1EiPU0d6BnqSH+hTvQsdabnqAs9T12pG3WnF6gHvUg9qRclUW/qQy9RX+pH/ellGkCv0EB6lQbRa5RMg2kIvU5D6Q0aRm/ScBpBI+ktGkVv02gaQ2NpHKXQeJpA79BEepcm0Xs0maZQKk2lafQ+TacZNJM+oFn0Ic2mOTSX5lEafUTzaQGl08e0kD6hDFpEi2kJLaVltJxW0EpaRatpDa2ldbSeNtBG2kSbaQttpW20nT6lHfQZ7aRdtJs+pz30BSF9SfvoK9pPX1MmfUMH6Fs6SN/RIfre96If6AgdpWN0nE7Qj3SSTtFpOkNn6Sc6Rz/TefIEIYYilKEKgzAmzBHGhjnDXOFVYe7w6jBPmDeMhNeEceG1Yb7wujB/WCAsGBYK48PCYZFQhya0IYVhWDQsFkbD68Pi4Q1hibBkWCosHbqwTJgQ3hiWDW8Ky4U3h+XDW8IK4a1hxbBS+Mi9VcLbwqrh7WG18I6wenhnWCOsGdYKa4d3hXXCu8O64T1hvfDesFx4X3h/+EDYIHwwbBg+FDYKHw4bh4+ETcJHw6Zhs7B52CJsGT4WtgofD1uHbcK24RNhu/DJsH34VJgYPh12CJ/5pf++BX+/PynsHfYJXwpfCr2/R86NzoumRT+Kzo8uiKZHP44ujH4SzYguii6OLokujS6LLo+uiK6Mroqujq6Jro2ui66Pboh6XzsHOHTCSadc4GJcDhfrcrpc7iqX213t8ri8LuKucXHuWpfPXefyuwKuoCvk4l1hV8RpZ5x15EJX1BVzUXe9K+5ucCVcSVfKlXbOlXEJroVr6Vq6Vu5x19q1cW3dE+4J96R70j3lnnJPuw7uGdfR/cV1cs+6zu4595x73nV13Vx394Lr4cbnufCaTHJ9XB/X1/V1/V1/N8ANcAPdQDfIDXLJLtkNcUPcUDfUDXPD3HA33I10I90oN8qNdqPdWDfWpbgUN8FNcBPdRDfJTXKT3WSX6lLdNDfNTXfTXdUZF44y2812c91cl+bS3HyXtWZMdwvdQpfhMtxit9gtdUvdcrfcrXQr3Wq32q11a916t95tdBvdZrfZbXVb3Xa33e1wO9xOn/fCpG6P2+v2un1un9vvvnaZ7ht3wH3rDrrv3CH3vTvsfnBH3FF3zB13J9yP7qQ75U67M+6s+8mdcz+78867lMj4yITIO5GJkXcjkyLvRSZHpkRSI1Mj0yLvR6ZHZkRmRj6IzIp8GJkdmROZG5kXSYt8FJkfWRBJj3wcWRj5JJIRWRRZHFkSWRpZFvG+8ObQF/XFfNRf74v7G3wJX9KX8qW982V8gr/Rl/U3+XL+Zl/e3+Ir+Ft9RV/JV/aP+qa+mW/uW/iW/jHfyj/uW/s2vq1/wrfzT/r2/imf6J/2HfwzvqP/i+/kn/Wd/XO+i3/ed/XdfHf/gu/hX/Q9fS+f5Hv7Pv4l39f38/39y36Af8UP9K/6Qf41n+wH+yH+dT/Uv+GH+Tf9cD/Cj4x5y4+6dIkM43yKH+8n+Hf8RP+un+Tf85P9FJ/qp/pp/n0/3c/wM/0Hfpb/0M/2c/xcP8+n+Y/8fL/Ap/uP/UL/ic/wiy7dVPbL/Qq/0q/yq/0av9av8+v9Br/Rb/Kb/Ra/1W/z2/2nfof/zO/0u/xu/7nf47/we/2Xfp//yu/3X/tM/40/4L/1B/13/pD/3h/2P/gj/qg/5o/7E/5Hf9Kf8qf9GX/W/+TP+Z/9ef6bNcYYY4yxf8j4y03x654Lt/N7/84Y8Vc79wGAq7cUyvzr/qwV5dr8F9r9RHy7CAA83avLQ5e2GjWSkpIu7pshISg2B+DST4KyxMDleBG0hSchEdpA2d/Nv5/odpb+YP7oLQC5/mpMLFyOL8//JQAm/c78jz0xcn6F8HTc/2P+OQAlil0ekxMux4ug7S/3V9pAub+Tf4FWf5B/zq9SAFr/1ZjccDm+nH8CPA7PQOKv9mSMMcYYY4wxxi7oJyp3unT9eek3Pn/v+jxeXR6TAy7Hf3R9zhhjjDHGGGOMsSvv2W7dn3osMbFNp3++Ue2P91H/2sy/NJrAv5oYN/6lhvcA/7dwAPBvTgiQ1ZD/ybPY9B85VvLFl87fdi094wP47yjln9G4wm9MjDHGGGOMsT/d5UX/r/9fXamEGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4yxbOjf/Y43+Ae+pe9KnyNjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDHGGGOMMcYYY4wxxhhjjDF2pf2fAAAA//+Bqfni")
r0 = syz_init_net_socket$nl_rdma(0x10, 0x3, 0x10)
sendmsg$TIPC_NL_BEARER_ENABLE(0xffffffffffffffff, &(0x7f0000001380)={0x0, 0x0, &(0x7f0000001340)={&(0x7f0000000200)=ANY=[@ANYBLOB='0\x00\x00\x00', @ANYRES16=0x0, @ANYBLOB="0000000007000000000003000000080001800400028014000280080050450acd00000800"], 0x30}}, 0x0)
sendmsg$netlink(r0, &(0x7f0000000180)={0x0, 0x0, &(0x7f0000000140)=[{&(0x7f0000000200)=ANY=[@ANYBLOB="140100002b000100000000000000001806"], 0x114}], 0x1}, 0x0)

[  636.327407][T16170] 8021q: adding VLAN 0 to HW filter on device batadv0
[  636.455955][T16333] loop1: detected capacity change from 0 to 256
[  636.475984][T16333] exfat: Deprecated parameter 'utf8'
[  636.533825][T16333] exFAT-fs (loop1): failed to load upcase table (idx : 0x00010000, chksum : 0xbe675ead, utbl_chksum : 0xe619d30d)
executing program 1:
r0 = socket$can_j1939(0x1d, 0x2, 0x7)
ioctl$ifreq_SIOCGIFINDEX_vcan(r0, 0x8933, &(0x7f0000000000)={'vxcan0\x00', <r1=>0x0})
bind$can_j1939(r0, &(0x7f0000000240)={0x1d, r1}, 0x18)
connect$can_j1939(r0, &(0x7f0000000080)={0x1d, r1, 0x3}, 0x18)
r2 = socket$can_j1939(0x1d, 0x2, 0x7)
r3 = socket$can_j1939(0x1d, 0x2, 0x7)
ioctl$ifreq_SIOCGIFINDEX_vcan(r3, 0x8933, &(0x7f0000001380)={'vxcan0\x00', <r4=>0x0})
bind$can_j1939(r2, &(0x7f0000000080)={0x1d, r4, 0x1}, 0x18)
r5 = socket$can_j1939(0x1d, 0x2, 0x7)
bind$can_j1939(r5, &(0x7f0000000100)={0x1d, r4, 0x2}, 0x18)
sendmmsg(r0, &(0x7f00000038c0)=[{{0x0, 0x0, 0x0}}, {{0x0, 0x0, &(0x7f0000001980)=[{&(0x7f0000001640)="03", 0x1}], 0x1}}], 0x2, 0x0)

[  637.526518][T16170] veth0_vlan: entered promiscuous mode
executing program 4:
r0 = socket$nl_netfilter(0x10, 0x3, 0xc)
sendmsg$IPCTNL_MSG_TIMEOUT_DEFAULT_SET(r0, &(0x7f0000000280)={0x0, 0x0, &(0x7f0000000080)={&(0x7f0000000000)=ANY=[@ANYBLOB="38000000030801040000000000000000020000001400048008000840102000000f0004400000004006000240000000000500030011"], 0x38}}, 0x0)

[  637.680474][T16170] veth1_vlan: entered promiscuous mode
executing program 3:
r0 = bpf$BPF_PROG_RAW_TRACEPOINT_LOAD(0x5, &(0x7f0000000200)={0x11, 0x3, &(0x7f00000000c0)=ANY=[@ANYBLOB="18000000000000000000000000080eff95"], &(0x7f0000000040)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x2}, 0x80)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f00000003c0)={&(0x7f00000002c0)='contention_end\x00', r0}, 0x10)
r1 = syz_genetlink_get_family_id$mptcp(&(0x7f0000000000), 0xffffffffffffffff)
r2 = socket$nl_generic(0x10, 0x3, 0x10)
sendmsg$MPTCP_PM_CMD_SET_FLAGS(r2, &(0x7f0000000500)={0x0, 0x0, &(0x7f00000004c0)={&(0x7f0000000040)=ANY=[@ANYBLOB="18000000", @ANYRES16=r1, @ANYBLOB="f70300000000a6a351550300000004000180"], 0x18}}, 0x0)

executing program 4:
mmap(&(0x7f0000000000/0xff5000)=nil, 0xff5000, 0x0, 0x200000005c831, 0xffffffffffffffff, 0x0)
madvise(&(0x7f0000000000/0x600000)=nil, 0x600003, 0x19)

[  637.844322][T16170] veth0_macvtap: entered promiscuous mode
executing program 4:
mmap(&(0x7f0000000000/0xff5000)=nil, 0xff5000, 0x0, 0x200000005c831, 0xffffffffffffffff, 0x0)
madvise(&(0x7f0000000000/0x600000)=nil, 0x600003, 0x19)

[  637.890006][T16170] veth1_macvtap: entered promiscuous mode
executing program 4:
seccomp$SECCOMP_SET_MODE_FILTER_LISTENER(0x1, 0x0, &(0x7f0000000040)={0x1, &(0x7f0000000000)=[{0x6, 0x0, 0x0, 0x7fff6ffc}]})
r0 = signalfd(0xffffffffffffffff, &(0x7f00000001c0), 0x8)
mkdir(&(0x7f0000000280)='./control\x00', 0x0)
close(r0)
r1 = inotify_init1(0x0)
fcntl$setstatus(r1, 0x4, 0x2c00)
r2 = gettid()
fcntl$setown(r0, 0x8, r2)
rt_sigprocmask(0x0, &(0x7f0000000000)={[0xfffffffffffffffd]}, 0x0, 0x8)
rt_sigtimedwait(&(0x7f00000002c0)={[0xffeffffffffffff6]}, 0x0, 0x0, 0x8)
inotify_add_watch(r1, &(0x7f0000000040)='./control\x00', 0xa0000000)
rmdir(&(0x7f0000000080)='./control\x00')
getresgid(&(0x7f00000037c0), &(0x7f0000003800), &(0x7f0000003840))

[  637.994301][T16170] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3e) already exists on: batadv_slave_0
[  638.036719][T16170] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
executing program 3:
r0 = socket$pppoe(0x18, 0x1, 0x0)
r1 = socket$phonet(0x23, 0x2, 0x1)
ioctl$sock_SIOCETHTOOL(r1, 0x8946, &(0x7f00000028c0)={'team_slave_1\x00', &(0x7f0000002880)=@ethtool_sfeatures})
r2 = socket$alg(0x26, 0x5, 0x0)
bind$alg(r2, &(0x7f0000000140)={0x26, 'rng\x00', 0x0, 0x0, 'drbg_pr_sha512\x00'}, 0x58)
accept(r2, &(0x7f0000000040), 0x0)
connect$pppoe(r0, &(0x7f0000000000)={0x18, 0x0, {0x401, @dev={'\xaa\xaa\xaa\xaa\xaa', 0xb}, 'ip_vti0\x00'}}, 0x1e)

executing program 1:
r0 = socket$inet_dccp(0x2, 0x6, 0x0)
bind$inet(r0, &(0x7f0000000180)={0x2, 0x4e20, @loopback}, 0x10)
connect$inet(r0, &(0x7f0000000140)={0x2, 0x0, @dev={0xac, 0x14, 0x14, 0x29}}, 0x10)
shutdown(r0, 0x0)

[  638.079206][T16170] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3e) already exists on: batadv_slave_0
[  638.108376][T16170] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
[  638.154098][T16170] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3e) already exists on: batadv_slave_0
[  638.185962][T16170] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
executing program 4:
syz_mount_image$ext4(&(0x7f0000000440)='ext4\x00', &(0x7f0000000480)='./file0\x00', 0x248, &(0x7f0000000000), 0xfd, 0x48d, &(0x7f0000000940)="$eJzs3M1rHOUfAPDvzG6SX1+TX60vrdVGq1h8SZq0akHBFxA8KAh6qCeJSVpq00aaCLYEG6XUi6AF7yJ4EfwLPHkS9SR41bsUivTS6mllMrPrJtnNSzfJptnPByY7z+7MPt/vzDwzz8zsJICO1Z/9SSJ2RsTvEdEbEenCCbblL7duzIz+fWNmNIlK5c2/kmy2uHljZrQ6aVK87sgL5eyL0stJvNig3qkLF8+MTEyMny/Kg9Nn3x+cunDxqdNnR06Nnxo/N3z8+LGjQ88+M/z0muSZxXRz/0eTB/a9+vbV10dPXH335++SuqDr82jRc7210ZnaMlno0TWqbLPYVTeelNsYCKvSExHZ6uqaa/+9Ubq8u/ZZb7zySVuDA9ZVpVKpDDf/eLYCbGFJtDsCoD2qB/rs/Lc6bFDXY1O4/lJ+ApTlfasY8k/K+XWQnvzcaNc61d8fESdm//kqG2LV1yG61ikqAGAr+yHr/zzZoP9Xjrinbrrdxb2hvoj4f0TsiYi7ImJvRNwd+bT3RsR9javpf6dJ/f0Lyov7P+m1FtJbVtb/e764tzW//1e7C9ZXKkq75vLvSk6enhg/UiyTw9HVk5WHGn57EjGbvf72ebP66/t/2ZDVX+0LFnFcK/fMn2dsZHqk5cQL1z+O2F9ulH8S5f+yiH0Rsf826zj9+LcH5r9Tqo0tn/8S1uA+U+XriMfy9T8bC/KvSpa+Pzn4v5gYPzJY3SoW++XXK280qz/PP42l89/WeqJNZOt/e6Pt/4Va/n1J/f3aqUVf0b1cHVf++LTpOc3tbv/dyVvzKv9wZHr6/FBEd/La4vfrLnBXy9Xps/wPH2rc/vcU82T53x8R2Ub8QEQ8GBEHi9gfioiHI+LQEvn/9PIj7zXN/2AL2/8ayPIfa7j/a7b+Vz9SOvPj983qX9n6P1YtzAW1kv3fSgNsZdkBAADAnSKNiJ2RpAO18TQdGMh/L783tqcTk1PTT5yc/ODcWP6MQF90pdUrXb1110OHimvD1fJwUb5UlI8W142/LG2bKw+MTk6MtTt56HA7mrT/zJ+ldkcHrDvPa0Hn0v6hc91++7fngDvdMq043ag4gI3nKA6dq1H7v1RfSCL/lTyw5Tj+Q+eqtf8vVjBx3eNeCx/eBO48Sx3/K70bGAiw4fT/oSO18lz/phiJbyKWnibZLKGuauSzVmYvb0CEkbZx+XS3ZaUMlyLauEmUV/pfLeJC5VLLlbZ7zwQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALA2/g0AAP//oVvkeQ==")
mount$tmpfs(0x0, &(0x7f0000000080)='./file0/../file0\x00', &(0x7f00000000c0), 0x0, 0x0)
lsetxattr$system_posix_acl(&(0x7f0000000000)='./file0\x00', &(0x7f0000000180)='system.posix_acl_default\x00', &(0x7f0000000380)=ANY=[@ANYBLOB="0200000001000000000000000400000000000000100000000000000020"], 0x24, 0x0)
llistxattr(&(0x7f0000000280)='./file0\x00', 0x0, 0x2)

[  638.207319][T16170] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3e) already exists on: batadv_slave_0
[  638.242395][T16170] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
[  638.271714][T16170] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3e) already exists on: batadv_slave_0
[  638.307106][T16170] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
executing program 1:
r0 = bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x13, 0x4, &(0x7f00000003c0)=@framed={{}, [@call={0x85, 0x0, 0x0, 0x11}]}, &(0x7f0000000640)='syzkaller\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_PROG_TEST_RUN(0xa, &(0x7f0000000240)={r0, 0x0, 0x14, 0x14, &(0x7f00000002c0)="0000ffffffffa000", &(0x7f0000000300)=""/8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x4c)

[  638.335518][T16170] batman_adv: batadv0: Interface activated: batadv_slave_0
[  638.350532][T16360] loop4: detected capacity change from 0 to 512
[  638.380988][T16170] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3f) already exists on: batadv_slave_1
[  638.387381][T16360] EXT4-fs (loop4): blocks per group (8192) and clusters per group (2304) inconsistent
[  638.416704][T16170] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
[  638.438327][T16170] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3f) already exists on: batadv_slave_1
[  638.473757][T16170] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
executing program 1:
r0 = socket$nl_generic(0x10, 0x3, 0x10)
r1 = syz_genetlink_get_family_id$devlink(&(0x7f0000000240), 0xffffffffffffffff)
sendmsg$DEVLINK_CMD_PORT_UNSPLIT(r0, &(0x7f0000001380)={0x0, 0x0, &(0x7f0000001340)={&(0x7f0000001280)={0x3c, r1, 0x1, 0x0, 0x0, {0xb}, [{{@nsim={{0xe}, {0xf, 0x2, {'netdevsim', 0x0}}}, {0x8}}}]}, 0x3c}}, 0x0)

[  638.492917][T16170] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3f) already exists on: batadv_slave_1
[  638.520351][T16325] loop2: detected capacity change from 0 to 32768
[  638.527149][T16170] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
[  638.540383][T16170] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3f) already exists on: batadv_slave_1
[  638.551687][T16170] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
[  638.563779][T16170] batman_adv: The newly added mac address (aa:aa:aa:aa:aa:3f) already exists on: batadv_slave_1
executing program 1:
syz_mount_image$ext4(&(0x7f0000000180)='ext4\x00', &(0x7f0000000000)='./bus\x00', 0x21081e, &(0x7f00000001c0)={[{@grpquota}, {@inode_readahead_blks={'inode_readahead_blks', 0x3d, 0x800}}, {@minixdf}]}, 0x1, 0x4fa, &(0x7f00000005c0)="$eJzs3c9vG1kdAPCvnThx0uwmu+wBEOyW3YWCqjqJuxut9gDLCSFUCdEjSG1I3CiKHUexU5rQQ3rmikQlTnDkD+DcE3cuCG5cygGJHxGoQeLg1YwnqZvaTdQkdhR/PtJo3ps39fe9pvNe/U3iF8DQuhoRuxExFhF3I2I6u57LjvisfST3Pdt7uLS/93ApF63W7X/l0vbkWnT8mcSV7DWLEfGj70X8NPdy3Mb2ztpitVrZzOqzzdrGbGN758ZqbXGlslJZL5cX5hfmPrn5cfnMxvpebSwrffXpH3e/9fOkW1PZlc5xnKX20AuHcRKjEfGD8wg2ACPZeMYG3RFeSz4i3o6I99PnfzpG0q8mAHCZtVrT0ZrurAMAl10+zYHl8qUsFzAV+Xyp1M7hvROT+Wq90bx+r761vtzOlc1EIX9vtVqZy3KFM1HIJfX5tPy8Xj5SvxkRb0XEL8cn0nppqV5dHuR/fABgiF05sv7/d7y9/gMAl1xx0B0AAPrO+g8Aw8f6DwDDx/oPAMOnvf5PDLobAEAfef8PAMPH+g8AQ+WHt24lR2s/+/zr5fvbW2v1+zeWK421Um1rqbRU39wordTrK+ln9tSOe71qvb4x/1FsPZj59kajOdvY3rlTq2+tN++kn+t9p1JI79rtw8gAgF7eeu/JX3LJivzpRHpEx14OhYH2DDhv+UF3ABiYkUF3ABgYu33B8DrFe3zpAbgkumzR+4Jit18QarVarfPrEnDOrn1J/h+GVUf+308Bw5CR/4fhJf8Pw6vVyp10z/846Y0AwMUmxw/0+P7/29n5d9k3B36yfPSOx+fZKwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALjYDvb/LWV7gU9FPl8qRbwRETNRyN1brVbmIuLNiPjzeGE8qc8PuM8AwGnl/57L9v+6Nv3h1AtN7145LI5FxM9+fftXDxabzc0/RYzl/j1+cL35OLte7n/vAYDjHazT6bnjjfyzvYdLB0c/+/OP70ZEsR1/f28s9g/jj8Zoei5GISIm/5PL6m25jtzFaew+iogvdht/LqbSHEh759Oj8ZPYb/Q1fv6F+Pm0rX1O/i6+cAZ9gWHzJJl/Puv2/OXjanru/vwX0xnq9LL5L3mppf10Dnwe/2D+G+kx/109aYyP/vD9dmni5bZHEV8ejTiIvd8x/xzEz/WI/+EJ4//1K+++36ut9ZuIa9E9fmes2WZtY7axvXNjtba4UlmprJfLC/MLc5/c/Lg8m+aoZ3uvBv/89PqbvdqS8U/2iF88ZvxfP+H4f/v/uz/+2ivif/ODbvHz8c4r4idr4jdOGH9x8vfFXm1J/OUe4z/u63/9hPGf/m3npW3DAYDBaWzvrC1Wq5VNBYWLX0j+yV6AbnQtfKdfscaie9MvPmg/00eaWq3XitVrxjiLrBtwERw+9BHxv0F3BgAAAAAAAAAAAAAA6Kofv7E06DECAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABweX0eAAD//19xzyM=")
quotactl$Q_SETQUOTA(0xffffffff80000801, &(0x7f0000000040)=@loop={'/dev/loop', 0x0}, 0x0, &(0x7f0000000100)={0x0, 0x1, 0x0, 0x0, 0x1, 0x5, 0x0, 0x0, 0x9d})

[  638.589364][T16325] XFS (loop2): Mounting V5 Filesystem a2f82aab-77f8-4286-afd4-a8f747a74bab
[  638.593676][T16170] batman_adv: It is strongly recommended to keep mac addresses unique to avoid problems!
[  638.664292][T16170] batman_adv: batadv0: Interface activated: batadv_slave_1
[  638.703655][T16377] loop1: detected capacity change from 0 to 512
executing program 3:
r0 = socket$inet6_sctp(0xa, 0x5, 0x84)
setsockopt$inet_sctp6_SCTP_SOCKOPT_BINDX_ADD(r0, 0x84, 0x64, &(0x7f0000000080)=[@in={0x2, 0x4e20, @empty}], 0x10)
getsockopt$inet_sctp6_SCTP_SOCKOPT_CONNECTX3(r0, 0x84, 0x6f, &(0x7f0000000280)={0x0, 0x48, &(0x7f00000000c0)=[@in6={0xa, 0x4e20, 0x0, @loopback={0x0, 0xac14140b}}, @in6={0xa, 0x4e20, 0x0, @rand_addr=' \x01\x00'}, @in={0x2, 0x4e20, @private=0xa010102}]}, &(0x7f00000002c0)=0x10)

[  638.729543][T16325] XFS (loop2): Ending clean mount
[  638.738140][T16170] netdevsim netdevsim0 netdevsim0: set [1, 0] type 2 family 0 port 6081 - 0
[  638.758222][T16170] netdevsim netdevsim0 netdevsim1: set [1, 0] type 2 family 0 port 6081 - 0
executing program 4:
r0 = openat$dsp(0xffffffffffffff9c, &(0x7f0000000200), 0x0, 0x0)
ioctl$SNDCTL_DSP_SPEED(r0, 0xc0045002, &(0x7f0000000080)=0x40000001)
ioctl$SNDCTL_DSP_SUBDIVIDE(r0, 0xc0045009, &(0x7f0000000000)=0x1)
ppoll(&(0x7f00000001c0)=[{r0}], 0x1, 0x0, 0x0, 0x0)

[  638.775629][T16170] netdevsim netdevsim0 netdevsim2: set [1, 0] type 2 family 0 port 6081 - 0
[  638.784959][T16170] netdevsim netdevsim0 netdevsim3: set [1, 0] type 2 family 0 port 6081 - 0
[  638.812742][T16377] EXT4-fs (loop1): mounted filesystem 00000000-0000-0000-0000-000000000000 r/w without journal. Quota mode: writeback.
[  638.895697][   T29] audit: type=1800 audit(1715377318.424:985): pid=16325 uid=0 auid=4294967295 ses=4294967295 subj=_ op=collect_data cause=failed(directio) comm="syz-executor.2" name="file1" dev="loop2" ino=1062 res=0 errno=0
[  638.928064][T16377] ext4 filesystem being mounted at /root/syzkaller-testdir2797635398/syzkaller.RXJx0o/554/bus supports timestamps until 2038-01-19 (0x7fffffff)
[  638.964807][T14650] XFS (loop2): Metadata CRC error detected at xfs_allocbt_read_verify+0x41/0xd0, xfs_bnobt block 0x8 
[  639.042402][T14650] XFS (loop2): Unmount and run xfs_repair
[  639.075248][T14650] XFS (loop2): First 128 bytes of corrupted metadata buffer:
[  639.091073][T14650] 00000000: 41 42 33 42 00 00 00 02 ff ff ff ff ff ff ff ff  AB3B............
[  639.112273][T14650] 00000010: 00 00 00 00 00 00 00 08 00 00 00 01 00 00 00 10  ................
[  639.126169][T16386] wlan0: Created IBSS using preconfigured BSSID 50:50:50:50:50:50
executing program 1:
socketpair$nbd(0x1, 0x1, 0x0, &(0x7f00000007c0)={<r0=>0xffffffffffffffff})
ioctl$sock_SIOCETHTOOL(r0, 0x8946, &(0x7f0000000000)={'veth0_to_hsr\x00', &(0x7f0000000040)=@ethtool_perm_addr={0x4b, 0x44, "daf1684742d14158e6f99acdcb772855f138e5140db8f02a98d7bd744b87e35a1817484e8771cc93858cb08ed71c050fe993a7a00e703b38c3fd47c2e647513d3f046132"}})

[  639.142361][T14650] 00000020: a2 f8 2a ab 77 f8 42 86 af d4 a8 f7 00 a7 4b ab  ..*.w.B.......K.
[  639.151781][T16386] wlan0: Creating new IBSS network, BSSID 50:50:50:50:50:50
[  639.163766][T14650] 00000030: 00 00 00 00 5b fd 4f dd 00 00 00 05 00 00 00 01  ....[.O.........
[  639.180618][ T9171] EXT4-fs (loop1): unmounting filesystem 00000000-0000-0000-0000-000000000000.
[  639.190440][T14650] 00000040: 00 00 02 36 00 00 0d ca 00 00 00 00 00 00 00 00  ...6............
[  639.211756][T14650] 00000050: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
executing program 3:
r0 = socket$kcm(0x29, 0x2, 0x0)
ioctl$sock_kcm_SIOCKCMCLONE(r0, 0x89e1, 0x0)

[  639.249000][  T140] wlan1: Created IBSS using preconfigured BSSID 50:50:50:50:50:50
[  639.257078][T14650] 00000060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
[  639.257165][T14650] 00000070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
[  639.277528][T16381] XFS (loop2): metadata I/O error in "xfs_btree_read_buf_block+0x36f/0x5b0" at daddr 0x8 len 8 error 74
[  639.308766][T14980] XFS (loop2): Metadata CRC error detected at xfs_allocbt_read_verify+0x41/0xd0, xfs_bnobt block 0x8 
[  639.327517][T16381] XFS (loop2): page discard on page ffffea0001052600, inode 0x429, pos 0.
[  639.337202][T14980] XFS (loop2): Unmount and run xfs_repair
[  639.343041][T14980] XFS (loop2): First 128 bytes of corrupted metadata buffer:
[  639.354845][  T140] wlan1: Creating new IBSS network, BSSID 50:50:50:50:50:50
[  639.366596][T14980] 00000000: 41 42 33 42 00 00 00 02 ff ff ff ff ff ff ff ff  AB3B............
[  639.387111][T14980] 00000010: 00 00 00 00 00 00 00 08 00 00 00 01 00 00 00 10  ................
[  639.397109][T14980] 00000020: a2 f8 2a ab 77 f8 42 86 af d4 a8 f7 00 a7 4b ab  ..*.w.B.......K.
executing program 0:
r0 = bpf$PROG_LOAD(0x5, &(0x7f00000004c0)={0x6, 0xb, &(0x7f0000000240)=ANY=[@ANYBLOB="18000000000000e50000000000000000180100002020702500000000002020207b1af8ff00000000bfa100000000000007010000f8ffffffb702000008000000b70300001e334185850000007300000095"], &(0x7f00000000c0)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_PROG_TEST_RUN(0xa, &(0x7f0000000640)={r0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2}, 0x50)

[  639.407125][T14980] 00000030: 00 00 00 00 5b fd 4f dd 00 00 00 05 00 00 00 01  ....[.O.........
[  639.417352][T14980] 00000040: 00 00 02 36 00 00 0d ca 00 00 00 00 00 00 00 00  ...6............
[  639.426426][T14980] 00000050: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
[  639.435569][T14980] 00000060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
[  639.446301][T14980] 00000070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
executing program 0:
r0 = socket$inet6(0xa, 0x2, 0x0)
sendmsg$nl_route(0xffffffffffffffff, &(0x7f0000000000)={0x0, 0x0, &(0x7f0000000080)={&(0x7f0000000040)=@bridge_setlink={0x24, 0x13, 0x0, 0x0, 0x0, {}, [@IFLA_AF_SPEC={0x4}]}, 0x24}}, 0x0)
bind$inet6(r0, &(0x7f0000f5dfe4)={0xa, 0x4e20, 0x0, @empty}, 0x1c)
recvmmsg(r0, &(0x7f0000000040), 0x400000000000284, 0x2b, 0x0)
setsockopt$inet6_int(r0, 0x29, 0x2, &(0x7f00000000c0)=0x1bc6, 0x4)
sendto$inet6(r0, 0x0, 0x0, 0x0, &(0x7f0000000300)={0xa, 0x4e20, 0x0, @mcast1}, 0x1c)

[  639.476691][T16325] XFS (loop2): metadata I/O error in "xfs_btree_read_buf_block+0x36f/0x5b0" at daddr 0x8 len 8 error 74
[  639.509187][T16325] XFS (loop2): Metadata I/O Error (0x1) detected at xfs_trans_read_buf_map+0x663/0xad0 (fs/xfs/xfs_trans_buf.c:296).  Shutting down filesystem.
executing program 1:
r0 = bpf$BPF_PROG_RAW_TRACEPOINT_LOAD(0x5, &(0x7f0000000200)={0x11, 0x3, &(0x7f00000000c0)=ANY=[@ANYBLOB="18000000000000000000000000080eff95"], &(0x7f0000000040)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x2}, 0x80)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f00000003c0)={&(0x7f00000002c0)='contention_end\x00', r0}, 0x10)
r1 = syz_genetlink_get_family_id$mptcp(&(0x7f0000000000), 0xffffffffffffffff)
r2 = socket$nl_generic(0x10, 0x3, 0x10)
sendmsg$MPTCP_PM_CMD_SET_FLAGS(r2, &(0x7f0000000500)={0x0, 0x0, &(0x7f00000004c0)={&(0x7f0000000040)=ANY=[@ANYBLOB="18000000", @ANYRES16=r1, @ANYBLOB="f70300000000a6a351550300000004000180"], 0x18}}, 0x0)

executing program 2:
r0 = socket$inet6_sctp(0xa, 0x1, 0x84)
bind$inet6(r0, &(0x7f00004b8fe4)={0xa, 0x4e23, 0x0, @empty}, 0x1c)
sendto$inet6(r0, &(0x7f0000847fff)='X', 0x1, 0x0, &(0x7f000005ffe4)={0xa, 0x4e23, 0x0, @loopback}, 0x1c)
setsockopt$inet_sctp6_SCTP_PEER_ADDR_THLDS(r0, 0x84, 0x85, &(0x7f0000000780)={0x0, @in={{0x2, 0x0, @private}}, 0x0, 0x6}, 0x90)

executing program 3:
r0 = openat$kvm(0xffffffffffffff9c, &(0x7f0000000100), 0x0, 0x0)
r1 = ioctl$KVM_CREATE_VM(r0, 0xae01, 0x0)
ioctl$KVM_SET_USER_MEMORY_REGION(r1, 0x4020ae46, &(0x7f0000000400)={0x0, 0x0, 0x0, 0x20002000, &(0x7f0000000000/0x2000)=nil})
r2 = ioctl$KVM_CREATE_VCPU(r1, 0xae41, 0x0)
syz_kvm_setup_cpu$x86(0xffffffffffffffff, r2, &(0x7f0000000000/0x18000)=nil, &(0x7f0000000200)=[@text32={0x20, &(0x7f0000000080)="66660f3834a30300000066ba4000b072ee65890f09b805000000b9008800000f01d966baf80cb87cfb6d87ef66bafc0cb873000000ef8ee866baa000edb9640001c00f3266baf80cb848724881ef66bafc0c83c4c1792eed0f3accdfa2", 0x5d}], 0x1, 0x0, 0x0, 0x0)
sched_getattr(0x0, &(0x7f0000000000)={0x38}, 0x38, 0x0)
ioctl$KVM_RUN(r2, 0xae80, 0x0)

[  639.537298][T16325] XFS (loop2): Please unmount the filesystem and rectify the problem(s)
[  639.576075][T14884] XFS (loop2): Unmounting Filesystem a2f82aab-77f8-4286-afd4-a8f747a74bab
executing program 1:
r0 = bpf$BPF_PROG_RAW_TRACEPOINT_LOAD(0x5, &(0x7f0000000240)={0x11, 0x3, &(0x7f0000000040)=@framed, &(0x7f0000000000)='GPL\x00'}, 0x90)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f0000000200)={&(0x7f00000004c0)='contention_begin\x00', r0}, 0x10)
r1 = syz_init_net_socket$nl_generic(0x10, 0x3, 0x10)
r2 = syz_genetlink_get_family_id$nl802154(&(0x7f0000000dc0), 0xffffffffffffffff)
sendmsg$NL802154_CMD_DEL_SEC_LEVEL(r1, &(0x7f0000000f00)={0x0, 0x0, &(0x7f0000000ec0)={&(0x7f0000000e00)={0x14, r2, 0x1, 0x0, 0x0, {0x26}}, 0x14}}, 0x0)

executing program 0:
r0 = syz_genetlink_get_family_id$ipvs(&(0x7f00000001c0), 0xffffffffffffffff)
r1 = socket$nl_generic(0x10, 0x3, 0x10)
sendmsg$IPVS_CMD_NEW_DAEMON(r1, &(0x7f00000002c0)={0x0, 0x0, &(0x7f0000000280)={&(0x7f0000000080)={0x44, r0, 0x1, 0x0, 0x0, {}, [@IPVS_CMD_ATTR_DAEMON={0x30, 0x3, 0x0, 0x1, [@IPVS_DAEMON_ATTR_STATE={0x8}, @IPVS_DAEMON_ATTR_MCAST_IFN={0x14, 0x2, 'vcan0\x00'}, @IPVS_DAEMON_ATTR_SYNC_ID={0x8}, @IPVS_DAEMON_ATTR_MCAST_TTL={0x5, 0x8, 0xc}]}]}, 0x44}}, 0x0)

executing program 4:
r0 = socket$inet(0x2, 0x2, 0x0)
setsockopt$sock_int(r0, 0x1, 0xf, &(0x7f0000000040)=0x8, 0x4)
r1 = openat(0xffffffffffffff9c, &(0x7f0000000100)='./file1\x00', 0x42, 0x0)
close(r1)
bind$inet(r0, &(0x7f0000000200)={0x2, 0x4e20, @empty}, 0x10)
r2 = socket$inet(0x2, 0x2, 0x0)
setsockopt$sock_int(r2, 0x1, 0xf, &(0x7f0000000040)=0x8, 0x4)
bind$inet(r2, &(0x7f0000000200)={0x2, 0x4e20, @empty}, 0x10)
connect$inet(r1, &(0x7f0000000140)={0x2, 0x0, @loopback}, 0x10)
syz_emit_ethernet(0x32, &(0x7f0000000240)={@multicast, @empty, @void, {@ipv4={0x800, @udp={{0x5, 0x4, 0x0, 0x0, 0x24, 0x0, 0x0, 0x0, 0x11, 0x0, @dev, @multicast1}, {0x0, 0x4e20, 0x10, 0x0, @gue={{0x2}}}}}}}, 0x0)

executing program 0:
r0 = socket$nl_generic(0x10, 0x3, 0x10)
r1 = syz_genetlink_get_family_id$batadv(&(0x7f0000000280), 0xffffffffffffffff)
r2 = socket(0x1e, 0x5, 0x0)
ioctl$ifreq_SIOCGIFINDEX_batadv_mesh(r2, 0x8933, &(0x7f0000000040)={'batadv0\x00', <r3=>0x0})
sendmsg$BATADV_CMD_SET_MESH(r0, &(0x7f0000000380)={0x0, 0x0, &(0x7f0000000340)={&(0x7f00000002c0)={0x2c, r1, 0x1, 0x0, 0x0, {}, [@BATADV_ATTR_MESH_IFINDEX={0x8, 0x3, r3}, @BATADV_ATTR_GW_BANDWIDTH_DOWN={0x8}, @BATADV_ATTR_BRIDGE_LOOP_AVOIDANCE_ENABLED={0x5, 0x2e, 0x1}]}, 0x2c}}, 0x0)

executing program 1:
socket$nl_netfilter(0x10, 0x3, 0xc)
r0 = socket$alg(0x26, 0x5, 0x0)
bind$alg(r0, &(0x7f00000000c0)={0x26, 'skcipher\x00', 0x0, 0x0, 'cbc-twofish-3way\x00'}, 0x58)
setsockopt$ALG_SET_AEAD_AUTHSIZE(r0, 0x117, 0x5, 0x0, 0xf)
r1 = socket$inet_tcp(0x2, 0x1, 0x0)
setsockopt$inet_tcp_int(r1, 0x6, 0x210000000013, &(0x7f00000000c0)=0x100000001, 0x4)
setsockopt$inet_tcp_TCP_CONGESTION(r1, 0x6, 0xd, &(0x7f0000000040)='bbr\x00', 0x4)
setsockopt$inet_tcp_TCP_REPAIR_WINDOW(r1, 0x6, 0x1d, &(0x7f0000000200)={0x7}, 0x14)
bind$inet(r1, &(0x7f0000000080)={0x2, 0x4e21, @empty}, 0x10)
connect$inet(r1, &(0x7f0000000180)={0x2, 0x4e21, @local}, 0x10)
setsockopt$inet_tcp_TCP_REPAIR_OPTIONS(r1, 0x6, 0x16, &(0x7f0000000000)=[@mss, @sack_perm, @window={0x3, 0x7}, @mss={0x2, 0xfff}, @window={0x3, 0x0, 0x401}, @window], 0x20000000000000e4)
setsockopt$inet_tcp_TCP_CONGESTION(r1, 0x6, 0xd, &(0x7f0000000100)='bic\x00', 0x4)
setsockopt$inet_tcp_TCP_REPAIR(r1, 0x6, 0x13, &(0x7f00000001c0), 0xc7)
setsockopt$inet_tcp_int(r1, 0x6, 0x1e, &(0x7f00000037c0)=0x8, 0x4)
setsockopt$inet_tcp_TCP_REPAIR(r1, 0x6, 0x13, &(0x7f0000000240), 0x4)
sendto$inet(r1, &(0x7f0000000000), 0xffffffffffffff94, 0xb, 0x0, 0x0)
recvfrom$inet(r1, &(0x7f0000000080)=""/8, 0xfffffffffffffd0b, 0x1f4, 0x0, 0xfffffffffffffd25)

executing program 0:
prctl$PR_SET_SECCOMP(0x16, 0x2, &(0x7f0000000000)={0x1, &(0x7f00000000c0)=[{0x200000000006, 0x0, 0x0, 0x7ffc1ffb}]})
r0 = bpf$BPF_PROG_RAW_TRACEPOINT_LOAD(0x5, &(0x7f0000000180)={0x18, 0x5, &(0x7f0000000280)=ANY=[@ANYBLOB="1801000021000000000000003b810000850000006d000000070000000000000095"], &(0x7f0000000040)='syzkaller\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x2}, 0x80)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f0000000880)={&(0x7f0000000080)='kfree\x00', r0}, 0x10)
keyctl$get_keyring_id(0x6, 0x0, 0x0)

executing program 4:
syz_mount_image$ext4(&(0x7f0000000180)='ext4\x00', &(0x7f0000000000)='./bus\x00', 0x21081e, &(0x7f00000001c0)={[{@grpquota}, {@inode_readahead_blks={'inode_readahead_blks', 0x3d, 0x800}}, {@minixdf}]}, 0x1, 0x4fa, &(0x7f00000005c0)="$eJzs3c9vG1kdAPCvnThx0uwmu+wBEOyW3YWCqjqJuxut9gDLCSFUCdEjSG1I3CiKHUexU5rQQ3rmikQlTnDkD+DcE3cuCG5cygGJHxGoQeLg1YwnqZvaTdQkdhR/PtJo3ps39fe9pvNe/U3iF8DQuhoRuxExFhF3I2I6u57LjvisfST3Pdt7uLS/93ApF63W7X/l0vbkWnT8mcSV7DWLEfGj70X8NPdy3Mb2ztpitVrZzOqzzdrGbGN758ZqbXGlslJZL5cX5hfmPrn5cfnMxvpebSwrffXpH3e/9fOkW1PZlc5xnKX20AuHcRKjEfGD8wg2ACPZeMYG3RFeSz4i3o6I99PnfzpG0q8mAHCZtVrT0ZrurAMAl10+zYHl8qUsFzAV+Xyp1M7hvROT+Wq90bx+r761vtzOlc1EIX9vtVqZy3KFM1HIJfX5tPy8Xj5SvxkRb0XEL8cn0nppqV5dHuR/fABgiF05sv7/d7y9/gMAl1xx0B0AAPrO+g8Aw8f6DwDDx/oPAMOnvf5PDLobAEAfef8PAMPH+g8AQ+WHt24lR2s/+/zr5fvbW2v1+zeWK421Um1rqbRU39wordTrK+ln9tSOe71qvb4x/1FsPZj59kajOdvY3rlTq2+tN++kn+t9p1JI79rtw8gAgF7eeu/JX3LJivzpRHpEx14OhYH2DDhv+UF3ABiYkUF3ABgYu33B8DrFe3zpAbgkumzR+4Jit18QarVarfPrEnDOrn1J/h+GVUf+308Bw5CR/4fhJf8Pw6vVyp10z/846Y0AwMUmxw/0+P7/29n5d9k3B36yfPSOx+fZKwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALjYDvb/LWV7gU9FPl8qRbwRETNRyN1brVbmIuLNiPjzeGE8qc8PuM8AwGnl/57L9v+6Nv3h1AtN7145LI5FxM9+fftXDxabzc0/RYzl/j1+cL35OLte7n/vAYDjHazT6bnjjfyzvYdLB0c/+/OP70ZEsR1/f28s9g/jj8Zoei5GISIm/5PL6m25jtzFaew+iogvdht/LqbSHEh759Oj8ZPYb/Q1fv6F+Pm0rX1O/i6+cAZ9gWHzJJl/Puv2/OXjanru/vwX0xnq9LL5L3mppf10Dnwe/2D+G+kx/109aYyP/vD9dmni5bZHEV8ejTiIvd8x/xzEz/WI/+EJ4//1K+++36ut9ZuIa9E9fmes2WZtY7axvXNjtba4UlmprJfLC/MLc5/c/Lg8m+aoZ3uvBv/89PqbvdqS8U/2iF88ZvxfP+H4f/v/uz/+2ivif/ODbvHz8c4r4idr4jdOGH9x8vfFXm1J/OUe4z/u63/9hPGf/m3npW3DAYDBaWzvrC1Wq5VNBYWLX0j+yV6AbnQtfKdfscaie9MvPmg/00eaWq3XitVrxjiLrBtwERw+9BHxv0F3BgAAAAAAAAAAAAAA6Kofv7E06DECAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABweX0eAAD//19xzyM=")
quotactl$Q_SETQUOTA(0xffffffff80000801, &(0x7f0000000040)=@loop={'/dev/loop', 0x0}, 0x0, &(0x7f0000000100)={0x0, 0x1, 0x0, 0x0, 0x1, 0x5, 0x0, 0x0, 0x9d})

executing program 2:
r0 = socket$inet_dccp(0x2, 0x6, 0x0)
getsockopt$inet_int(r0, 0x10d, 0x11, &(0x7f0000000000), &(0x7f0000000080)=0x4)

executing program 3:
r0 = socket$nl_route(0x10, 0x3, 0x0)
sendmsg$nl_route(r0, &(0x7f0000000140)={0x0, 0x0, &(0x7f0000000100)={&(0x7f0000000080)=@ipv4_newrule={0x38, 0x20, 0x1, 0x0, 0x0, {}, [@FRA_GENERIC_POLICY=@FRA_OIFNAME={0x14, 0x11, 'veth0_vlan\x00'}, @FRA_GENERIC_POLICY=@FRA_FWMARK={0x8}]}, 0x38}}, 0x0)

[  640.449423][T16416] loop4: detected capacity change from 0 to 512
[  640.487206][   T29] audit: type=1326 audit(1715377320.014:986): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=_ pid=16418 comm="syz-executor.0" exe="/root/syz-executor.0" sig=0 arch=c000003e syscall=202 compat=0 ip=0x7f5fccc7dd69 code=0x7ffc0000
executing program 0:
r0 = socket$pppoe(0x18, 0x1, 0x0)
connect$pppoe(r0, &(0x7f0000000000)={0x18, 0x0, {0x4, @broadcast, 'veth0_vlan\x00'}}, 0x1e)
ioctl$PPPOEIOCSFWD(r0, 0x4008b100, 0x0)

executing program 2:
bpf$BPF_PROG_TEST_RUN(0xa, &(0x7f0000000440)={0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x50)
futex(&(0x7f0000004000), 0x5, 0x0, 0x0, &(0x7f0000004000), 0x92020000)
bpf$PROG_LOAD(0x5, 0x0, 0x0)
bpf$PROG_LOAD(0x5, 0x0, 0x0)
r0 = openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000080)='cpuacct.stat\x00', 0x275a, 0x0)
write$binfmt_script(r0, &(0x7f0000000040), 0x4000)

executing program 3:
r0 = socket$inet6_sctp(0xa, 0x801, 0x84)
sendto$inet6(r0, &(0x7f0000000180)='=', 0x1, 0x0, &(0x7f0000000200)={0xa, 0x0, 0x0, @private1}, 0x1c)
shutdown(r0, 0x1)
r1 = socket$inet6_sctp(0xa, 0x5, 0x84)
getsockopt$inet_sctp6_SCTP_MAX_BURST(r1, 0x84, 0xc, &(0x7f0000000000)=@assoc_value={<r2=>0x0}, &(0x7f0000000180)=0x8)
setsockopt$inet_sctp6_SCTP_STREAM_SCHEDULER_VALUE(r0, 0x84, 0x7c, &(0x7f0000000240)={r2}, 0x8)

[  640.590794][   T29] audit: type=1326 audit(1715377320.014:987): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=_ pid=16418 comm="syz-executor.0" exe="/root/syz-executor.0" sig=0 arch=c000003e syscall=202 compat=0 ip=0x7f5fccc7dd69 code=0x7ffc0000
[  640.619590][T16416] EXT4-fs (loop4): mounted filesystem 00000000-0000-0000-0000-000000000000 r/w without journal. Quota mode: writeback.
[  640.643294][   T29] audit: type=1326 audit(1715377320.034:988): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=_ pid=16418 comm="syz-executor.0" exe="/root/syz-executor.0" sig=0 arch=c000003e syscall=321 compat=0 ip=0x7f5fccc7dd69 code=0x7ffc0000
[  640.665007][T16416] ext4 filesystem being mounted at /root/syzkaller-testdir3208322292/syzkaller.v3fGEZ/29/bus supports timestamps until 2038-01-19 (0x7fffffff)
[  640.670259][   T29] audit: type=1326 audit(1715377320.034:989): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=_ pid=16418 comm="syz-executor.0" exe="/root/syz-executor.0" sig=0 arch=c000003e syscall=202 compat=0 ip=0x7f5fccc7dd69 code=0x7ffc0000
[  640.702993][   T29] audit: type=1326 audit(1715377320.044:990): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=_ pid=16418 comm="syz-executor.0" exe="/root/syz-executor.0" sig=0 arch=c000003e syscall=321 compat=0 ip=0x7f5fccc7dd69 code=0x7ffc0000
[  640.727411][T16429] futex_wake_op: syz-executor.2 tries to shift op by 32; fix this program
[  640.744844][   T29] audit: type=1326 audit(1715377320.044:991): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=_ pid=16418 comm="syz-executor.0" exe="/root/syz-executor.0" sig=0 arch=c000003e syscall=202 compat=0 ip=0x7f5fccc7dd69 code=0x7ffc0000
executing program 0:
r0 = bpf$BPF_PROG_RAW_TRACEPOINT_LOAD(0x5, &(0x7f0000000240)={0x11, 0x3, &(0x7f0000000040)=@framed, &(0x7f0000000000)='GPL\x00'}, 0x90)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f0000000200)={&(0x7f00000004c0)='contention_begin\x00', r0}, 0x10)
socket$nl_generic(0x10, 0x3, 0x10)
r1 = bpf$MAP_CREATE_RINGBUF(0x0, &(0x7f0000000180)={0x1b, 0x0, 0x0, 0x40000, 0x0, 0x0}, 0x48)
r2 = bpf$PROG_LOAD(0x5, &(0x7f0000000680)={0x11, 0xf, &(0x7f0000000340)=@ringbuf={{}, {{0x18, 0x1, 0x1, 0x0, r1}}, {}, [], {{}, {}, {0x85, 0x0, 0x0, 0x85}}}, &(0x7f0000001dc0)='syzkaller\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f00000003c0)={&(0x7f0000000140)='sys_enter\x00', r2}, 0x10)
openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000080)='pids.events\x00', 0x275a, 0x0)
socket(0x1e, 0x2, 0x0)
socket$nl_netfilter(0x10, 0x3, 0xc)
socket$igmp6(0xa, 0x3, 0x2)
socket$nl_generic(0x10, 0x3, 0x10)
r3 = socket$nl_route(0x10, 0x3, 0x0)
socket$inet6_tcp(0xa, 0x1, 0x0)
socket$inet6_mptcp(0xa, 0x1, 0x106)
socketpair(0x1, 0x20000000000001, 0x0, &(0x7f0000000100)={<r4=>0xffffffffffffffff})
getsockname$packet(r4, &(0x7f0000000100)={0x11, 0x0, <r5=>0x0, 0x1, 0x0, 0x6, @broadcast}, &(0x7f0000000080)=0x14)
sendmsg$nl_route(r3, &(0x7f0000000240)={0x0, 0x0, &(0x7f0000000180)={&(0x7f0000000100)=@dellink={0x20, 0x11, 0x1, 0x0, 0x0, {0x0, 0x0, 0x0, r5}}, 0x20}}, 0x0)

[  640.802346][   T29] audit: type=1326 audit(1715377320.044:992): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=_ pid=16418 comm="syz-executor.0" exe="/root/syz-executor.0" sig=0 arch=c000003e syscall=39 compat=0 ip=0x7f5fccc7b4e7 code=0x7ffc0000
executing program 4:
mkdir(&(0x7f0000002880)='./file0\x00', 0x0)
mount(0x0, &(0x7f0000000240)='./file0\x00', &(0x7f0000000280)='sysfs\x00', 0x0, 0x0)
r0 = open_tree(0xffffffffffffff9c, &(0x7f0000000640)='\x00', 0x89901)
move_mount(r0, &(0x7f0000000140)='.\x00', 0xffffffffffffff9c, &(0x7f0000000180)='./file0\x00', 0x0)
chroot(&(0x7f0000000000)='./file0\x00')
pivot_root(&(0x7f0000000040)='./file0/../file0/../file0\x00', &(0x7f0000000200)='./file0/../file0\x00')

[  640.877984][   T29] audit: type=1326 audit(1715377320.044:993): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=_ pid=16418 comm="syz-executor.0" exe="/root/syz-executor.0" sig=0 arch=c000003e syscall=15 compat=0 ip=0x7f5fccc411a9 code=0x7ffc0000
[  640.927985][T15853] EXT4-fs (loop4): unmounting filesystem 00000000-0000-0000-0000-000000000000.
[  640.939350][   T29] audit: type=1326 audit(1715377320.044:994): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=_ pid=16418 comm="syz-executor.0" exe="/root/syz-executor.0" sig=0 arch=c000003e syscall=250 compat=0 ip=0x7f5fccc7dd69 code=0x7ffc0000
executing program 3:
mkdirat(0xffffffffffffff9c, &(0x7f0000002040)='./file0\x00', 0x0)
bpf$MAP_CREATE(0x0, &(0x7f0000000640)=@base={0x16, 0x0, 0x3, 0xff, 0x0, 0x1}, 0x48)
bpf$PROG_LOAD_XDP(0x5, 0x0, 0x0)
r0 = bpf$PROG_LOAD(0x5, 0x0, 0x0)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f0000000000)={&(0x7f0000000100)='kmem_cache_free\x00', r0}, 0x10)
r1 = openat$fuse(0xffffffffffffff9c, &(0x7f0000000300), 0x42, 0x0)
mount$fuse(0x0, &(0x7f00000020c0)='./file0\x00', &(0x7f0000002100), 0x0, &(0x7f0000002140)={{'fd', 0x3d, r1}, 0x2c, {'rootmode', 0x3d, 0x4000}})
read$FUSE(r1, &(0x7f00000021c0)={0x2020, 0x0, <r2=>0x0}, 0x2020)
write$FUSE_INIT(r1, &(0x7f0000004200)={0x50, 0x0, r2, {0x7, 0x1f, 0x0, 0xeea390}}, 0x50)
readlink(&(0x7f0000000040)='./file0/file0/file0/file0/file0\x00', &(0x7f0000000080)=""/167, 0xa7)
read$FUSE(r1, &(0x7f0000008bc0)={0x2020, 0x0, <r3=>0x0}, 0x2020)
write$FUSE_INIT(r1, &(0x7f0000000280)={0x50, 0x0, r3, {0x7, 0x24}}, 0x50)

executing program 4:
r0 = socket$nl_route(0x10, 0x3, 0x0)
sendmsg$nl_route(r0, &(0x7f0000000100)={0x0, 0x0, &(0x7f00000000c0)={&(0x7f0000000080)=ANY=[@ANYBLOB="300000001a000100000000000000000081800000", @ANYRES32=0x0, @ANYBLOB="00000000140001"], 0x30}}, 0x0)

executing program 4:
socketpair$unix(0x1, 0x5, 0x0, &(0x7f0000000000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})
sendmmsg$unix(r1, &(0x7f0000004080)=[{{0x0, 0x0, 0x0, 0x0, &(0x7f0000000040)=ANY=[@ANYBLOB="14000000000000000100000001000000", @ANYRES32=r0], 0x18}}], 0x1, 0x0)
sendmmsg$unix(0xffffffffffffffff, &(0x7f0000001980)=[{{0x0, 0x0, 0x0, 0x0, &(0x7f00000001c0)=ANY=[@ANYBLOB="14000000000000000100000001000000", @ANYRES32=r0], 0x18}}], 0x1, 0x0)
r2 = bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x11, 0xb, &(0x7f0000000180)=ANY=[@ANYBLOB="18000000000000000000000000000000180100002020702500000000002020207b1af8ff00000000bfa100000000000007010000f8ffffffb702000002000000b7030000faffffff850000002d00000095"], &(0x7f0000000040)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f00000000c0)={&(0x7f0000000040)='kmem_cache_free\x00', r2}, 0x10)
r3 = dup3(r1, r0, 0x0)
connect$unix(r3, &(0x7f0000000100)=@abs={0x1}, 0x6e)

executing program 3:
r0 = bpf$MAP_CREATE(0x0, &(0x7f00000009c0)=@base={0x5, 0x4, 0x1, 0x4}, 0x48)
close(r0)
r1 = bpf$MAP_CREATE(0x0, &(0x7f0000000000)=@base={0xe, 0x4, 0x4, 0x2, 0x0, 0x1}, 0x48)
r2 = bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x11, 0x14, &(0x7f00000002c0)=ANY=[@ANYBLOB="1800000000000000000000000000000018110000", @ANYRES32=r0, @ANYBLOB="0000000000000000b7080000000000007b8af8ff00000000bfa200000000000007020000f8ffffffb703000008000000b7040000000000208500000001000000180100002020702500000000002020207b1af8ff00000000bfa100000000000007010000f8ffffffb702000008000000b703000000000000850000000e00000095"], &(0x7f0000000040)='syzkaller\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f0000000180)={&(0x7f0000000140)='ext4_ext_remove_space_done\x00', r2}, 0x10)
r3 = openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000380)='blkio.bfq.io_queued_recursive\x00', 0x26e1, 0x0)
bpf$MAP_UPDATE_ELEM_TAIL_CALL(0x2, &(0x7f0000000600)={{r1}, &(0x7f00000003c0), &(0x7f00000005c0)=r3}, 0x20)
openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000240)='cgroup.controllers\x00', 0x26e1, 0x0)
openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000080)='cgroup.controllers\x00', 0x7a05, 0x1700)

executing program 1:
r0 = syz_usb_connect$hid(0x0, 0x36, &(0x7f00000011c0)=ANY=[@ANYBLOB="12010001090003206d0414c340000000000109022400010000a000090400000103010100092100080001220300090581", @ANYRES64], 0x0)
syz_usb_control_io$hid(r0, &(0x7f00000001c0)={0x24, &(0x7f0000001180)=ANY=[@ANYBLOB="00020c0000000c0002"], 0x0, 0x0, 0x0}, 0x0)
syz_usb_control_io$hid(r0, 0x0, 0x0)
syz_usb_control_io(r0, 0x0, 0x0)
syz_usb_control_io$hid(r0, 0x0, 0x0)
syz_usb_control_io(r0, 0x0, 0x0)
syz_usb_control_io$hid(r0, 0x0, &(0x7f0000000f40)={0x2c, &(0x7f0000000c80)={0x0, 0x0, 0x4, "e06b445a"}, 0x0, 0x0, 0x0, 0x0})
syz_usb_control_io(r0, 0x0, &(0x7f00000013c0)={0x84, 0x0, 0x0, 0x0, &(0x7f0000000f80)={0x20, 0x0, 0x4, {0x3}}, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0})

[  641.524058][T16429] loop2: detected capacity change from 0 to 32768
[  641.643951][T16429] bcachefs (loop2): mounting version 1.7: mi_btree_bitmap opts=metadata_checksum=none,data_checksum=xxhash,compression=gzip,nojournal_transaction_names
[  641.665718][T16429] bcachefs (loop2): recovering from clean shutdown, journal seq 10
[  641.689379][T16429] bcachefs (loop2): alloc_read... done
[  641.704935][T16429] bcachefs (loop2): stripes_read... done
[  641.710692][T16429] bcachefs (loop2): snapshots_read... done
[  641.720984][T16429] bcachefs (loop2): journal_replay... done
[  641.729026][T16429] bcachefs (loop2): resume_logged_ops... done
[  641.735746][   T57] usb 2-1: new high-speed USB device number 19 using dummy_hcd
[  641.742485][T16429] bcachefs (loop2): going read-write
[  641.752985][T16429] bcachefs (loop2): done starting filesystem
[  641.856076][T14884] bcachefs (loop2): shutting down
[  641.864652][T14884] bcachefs (loop2): going read-only
[  641.870053][T14884] bcachefs (loop2): finished waiting for writes to stop
[  641.895300][T14884] bcachefs (loop2): flushing journal and stopping allocators, journal seq 12
[  641.924518][T14884] bcachefs (loop2): flushing journal and stopping allocators complete, journal seq 14
[  641.946125][T14884] bcachefs (loop2): shutdown complete, journal seq 15
[  641.954526][T14884] bcachefs (loop2): marking filesystem clean
[  642.004999][   T57] usb 2-1: Using ep0 maxpacket: 32
[  642.071899][T14884] bcachefs (loop2): shutdown complete
executing program 4:
r0 = socket$tipc(0x1e, 0x5, 0x0)
setsockopt$TIPC_GROUP_JOIN(r0, 0x10f, 0x87, &(0x7f0000000080)={0x42}, 0x10)
setsockopt$TIPC_GROUP_JOIN(r0, 0x10f, 0x87, &(0x7f0000000100)={0x43, 0x0, 0x3, 0x3}, 0x10)

[  642.155346][   T57] usb 2-1: config 0 interface 0 altsetting 0 endpoint 0x81 has an invalid bInterval 255, changing to 11
[  642.166735][   T57] usb 2-1: config 0 interface 0 altsetting 0 endpoint 0x81 has invalid maxpacket 59391, setting to 1024
[  642.179335][   T57] usb 2-1: New USB device found, idVendor=046d, idProduct=c314, bcdDevice= 0.40
executing program 0:
syz_mount_image$hfsplus(&(0x7f0000000600), &(0x7f0000000140)='./bus\x00', 0x10, &(0x7f0000000640)=ANY=[@ANYBLOB="666f72636500006961e38c8000000000000000303030303030073f41101bb03031392c6372656136d9bb3d25f4ea8366a8716cc24cf9130200cb37712402bdc8023a1ceb6cff75724acdc6bf741701005345d303007fb7829750340644608b887292d3e1821a704e46584fb946cf3b277b74f2c0467d63f3d94d7b3f3b27b1b953c928a63d7786e23b2dcf98f4bbb4903a06ab8c627b7bf4b1ce089d07bc4ab93295be12b82c458f84c3ae25bcf2d853e98b873fd8aebab2359657997a39667f5d6beb1aca91b0aeb79f37ab02050bde52e8c30da6e0039010c83791d1d7847f5116b544b9f372663913ffa789b210260be4780c061fdfed191df07d52d68db92963ef8fbe8511ae0ce4abceb6516b9873787883ad79744700e9ebbe4a0f564675ca9e56f4cecc8de78f7ca803d7c0f266c3b5cb9b320dd6e926c5b88808cc435331a9a75bb9f9ca0f4d0056a114daeb4c5e3171de79ffffffff1f7d0e9127d8fdd83051dbb6fcb25b8d09967293855e13c0d4bb8eec9bf81b5375dbe9eced05b5b60cb8c9f158f18dede7224655e9010c60315b9645a78767a5ca8ebfd7d2d4e6ae9706f00ae9d597e95a5e62897e9a389d9143e6eb069e037c29ffffffffbcd7fe7880f6675464cbaa3b7d500ce2e97685d411128b72b6fa8a579221c6b26e66f61551069b4b16dfdc1f6e725bd75aa9872cf6de468df00375c85a78179518c6f1ec0000bba7b11cbe385859962f41ba4c2dd6303fdb36d9829c0008ba31a150c0f05d0aa83faf5336e00b769a5e4159a22e385e5f9912fa1110e057b4a96198be5f3ed9394a7d34010000000006000000000000004333067b81ae9c93cf2f992209565d76aaa1447c343e11387d691903f3430a3c31e4f13fcaf3f0b957f8d72bea2cb38a986e3d47d5725c8355cfc4af88bdf70b2d90f500518076aa83778a3f255e9b2ca5f6b76b385afc201d596f66f4b238c79f77b6e3b7d11d9e817063411c5e5db815aae653b0fe977d1906763c6c21323d072895f377be1f01000100b638360584bfc2e139765c52bf0590b08398266c8a41055669f3c4075c87e9d3fbfab6bfbd59b12a2e0c0de44b19c10eeb9d960e9f4e4d07000000db6c589ce07d74f037ca6a0024d4403d0349dc87ef2fc73d1070f7dee3f173e931360467368a4356a029c93dc4ff72de5c5ff12795ca39b76e5a27d3f50414c990149b7b168b291dbfde8e6fec83c1c1ec5338a7fde3f58c8b2d54b42a1258ca6ed9fdd657704e84627d61049764a0c1b258e3cf38f9f3e1fcff9bf12947efdf2b943a912d36877bd67d149861167a9a1fd8844f74fc5a33b135d5620e5c3f29a87cc4c95bf9ad71f7c28cd9687a7a135e0a9b1926dc8a053cee53c649ff33b1ffff4f1db7f2a824531fea00000000000000000000000000000000b8ece81c7469127bdb79169ce44609ffb833513668b2c70a2e5b271bf283de11c8c25ac2361a79218ca640014a12a6d88156d4ac80a7cfd44acc61965b066d45fd3e88914bbc6f012b13398f00923e75931a0a4b44b32660e2e80e2d78438cfdd075bfad3027f175044b4d4ec2e30417e6becb6aaa8d6c0fb4271df7688a4b70cc7c027f4501017952a908971004b570bc0b9887b3490bc15b7c90228a7e3770f498eeb8dafbf072e89350348d218ca7e07e174f53ec873c13c1a299080215201e2487a194b51a300f67c5a60f3249508a5a07391951ee7e31e594775f589706a7e5a2f8b5f614746f721bd6bb85752cbba9c3a193dcb73e0e35fb6082637ddb74a4a65513981b563a72a5d23775dfa94917ae84638e4ad70f0d0ee85c3efa2b74bb82ed3f2951bfd54884b7506fdfbbd965d908e47a404667f642cbf4634808a74fcdd5903784a18e2d717a1b45cb74e0e5", @ANYRES32, @ANYRES16, @ANYRESHEX], 0x3, 0x5f9, &(0x7f0000002d00)="$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")

[  642.201154][   T57] usb 2-1: New USB device strings: Mfr=0, Product=0, SerialNumber=0
executing program 3:
r0 = socket(0xa, 0x3, 0x3a)
setsockopt$MRT6_DEL_MIF(r0, 0x29, 0xc8, 0x0, 0xc000000)
setsockopt$MRT6_DONE(r0, 0x29, 0xcf, 0x0, 0x0)

executing program 2:
r0 = socket(0x1, 0x3, 0x0)
connect$packet(r0, &(0x7f0000000380)={0x11, 0x0, 0x0, 0x1, 0x0, 0x6, @multicast}, 0x14)

[  642.260283][   T57] usb 2-1: config 0 descriptor??
executing program 4:
r0 = socket$kcm(0x10, 0x2, 0x10)
sendmsg$kcm(r0, &(0x7f00000000c0)={0x0, 0x0, &(0x7f0000000480)=[{&(0x7f0000000000)="1400000010003507d25a806f8c6394f90324fc60", 0x14}], 0x1}, 0x0)
recvmsg$kcm(r0, &(0x7f0000006440)={0x0, 0x0, 0x0}, 0x0)
recvmsg$kcm(r0, &(0x7f0000000380)={0x0, 0x0, &(0x7f00000027c0)=[{&(0x7f0000000500)=""/4096, 0x500}, {&(0x7f0000001500)=""/4082, 0xff2}], 0x2}, 0x0)

[  642.293087][T16462] loop0: detected capacity change from 0 to 1024
[  642.305361][T16448] raw-gadget.0 gadget.1: fail, usb_ep_enable returned -22
[  642.327004][   T57] hub 2-1:0.0: USB hub found
[  642.336037][T16462] hfsplus: failed to load attributes file
executing program 4:
r0 = syz_init_net_socket$llc(0x1a, 0x2, 0x0)
r1 = syz_init_net_socket$bt_hci(0x1f, 0x3, 0x1)
bind$bt_hci(r1, &(0x7f0000000280)={0x1f, 0xffff, 0x3}, 0x6)
io_setup(0x6, &(0x7f00000002c0)=<r2=>0x0)
io_submit(r2, 0x1, &(0x7f0000000340)=[&(0x7f0000000100)={0x2000000000, 0x4, 0x0, 0x1, 0x0, r1, &(0x7f0000000040)="0300ffff0000", 0x6}])
listen(r0, 0x0)
r3 = add_key$keyring(&(0x7f0000000080), &(0x7f00000000c0)={'syz', 0x2}, 0x0, 0x0, 0xfffffffffffffff8)
add_key$keyring(&(0x7f0000000000), &(0x7f0000000040)={'syz', 0x1}, 0x0, 0x0, r3)

executing program 3:
bpf$ENABLE_STATS(0x20, 0x0, 0x0)
r0 = bpf$MAP_CREATE(0x0, &(0x7f0000000640)=@base={0x16, 0x0, 0x4, 0xff, 0x0, 0x1}, 0x48)
bpf$PROG_LOAD_XDP(0x5, &(0x7f0000000a40)={0x3, 0xc, &(0x7f0000000440)=ANY=[@ANYBLOB="1800000000000000000000000000000018110000", @ANYRES32=r0, @ANYBLOB="0000000000000000b7080000000000007b8af8ff00000000bfa200000000000007020000f8ffffffb703000008000000b704000000000000850000005900000095"], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x25, 0xffffffffffffffff, 0x8, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 0x42}, 0x90)
bpf$MAP_UPDATE_ELEM_TAIL_CALL(0x2, &(0x7f00000003c0)={{r0}, 0x0, &(0x7f0000000040)}, 0x20)
r1 = bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x11, 0xc, &(0x7f0000000440)=ANY=[], &(0x7f0000000240)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f0000000300)={&(0x7f00000003c0)='workqueue_activate_work\x00', r1}, 0x10)
bpf$PROG_LOAD(0x5, &(0x7f0000000740)={0x0, 0x14, 0x0, &(0x7f0000000240)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)

executing program 0:
r0 = socket$pppl2tp(0x18, 0x1, 0x1)
r1 = socket$inet6_udp(0xa, 0x2, 0x0)
connect$pppl2tp(r0, &(0x7f0000000240)=@pppol2tpin6={0x18, 0x1, {0x0, r1, 0x8, 0x0, 0x0, 0x0, {0xa, 0x0, 0x0, @rand_addr=' \x01\x00'}}}, 0x32)
bind$inet6(0xffffffffffffffff, &(0x7f0000000280)={0xa, 0x0, 0x5, @rand_addr=' \x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'}, 0x1c)
r2 = openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000080)='memory.events\x00', 0x275a, 0x0)
write$binfmt_script(r2, &(0x7f0000000100), 0xfecc)
mmap(&(0x7f0000000000/0x3000)=nil, 0x3000, 0x1, 0x12, r2, 0x0)
writev(r0, &(0x7f0000000180)=[{0x0}], 0x1)

[  642.555061][   T57] hub 2-1:0.0: 2 ports detected
executing program 4:
r0 = open(&(0x7f0000000180)='./bus\x00', 0x14d27e, 0x0)
mmap(&(0x7f0000000000/0x600000)=nil, 0x600000, 0x27fffff, 0x4002011, r0, 0x0)
fallocate(r0, 0x0, 0x0, 0x8006)
r1 = socket$unix(0x1, 0x2, 0x0)
ioctl$ifreq_SIOCGIFINDEX_vcan(r1, 0x8933, &(0x7f0000000400)={'vxcan1\x00', <r2=>0x0})
r3 = socket$can_bcm(0x1d, 0x2, 0x2)
connect$can_bcm(r3, &(0x7f0000000200)={0x1d, r2}, 0x10)
sendmsg$can_bcm(r3, &(0x7f0000000480)={0x0, 0x0, &(0x7f0000000040)={&(0x7f0000000580)=ANY=[@ANYBLOB="01000000e73932cb7e4d5d5bdbe70000", @ANYRES64=0x0, @ANYRES64=0x0, @ANYRES64=r2, @ANYRES64=r1, @ANYBLOB="3bf81bb9e9"], 0x20000600}}, 0x0)

executing program 3:
r0 = openat$vicodec0(0xffffffffffffff9c, &(0x7f0000000180), 0x2, 0x0)
ioctl$VIDIOC_ENUM_FMT(r0, 0xc0405602, &(0x7f0000000040)={0x58, 0xa, 0x0, "3258ae1e10006c5d3500"})

executing program 0:
unshare(0xa000600)
r0 = syz_open_dev$sndctrl(&(0x7f0000000040), 0x0, 0x0)
ioctl$SNDRV_CTL_IOCTL_SUBSCRIBE_EVENTS(r0, 0xc00455d0, 0x0)

executing program 0:
r0 = socket$inet_dccp(0x2, 0x6, 0x0)
bind$inet(r0, &(0x7f0000000180)={0x2, 0x4e20, @loopback}, 0x10)
connect$inet(r0, &(0x7f0000000140)={0x2, 0x0, @dev={0xac, 0x14, 0x14, 0x29}}, 0x10)
shutdown(r0, 0x0)

executing program 4:
pipe2(&(0x7f0000000080)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff}, 0x0)
splice(r0, &(0x7f0000000100)=0x7, r0, &(0x7f0000000140)=0x1eb, 0xa823, 0x3)
r2 = socket$nl_netfilter(0x10, 0x3, 0xc)
bpf$BPF_PROG_RAW_TRACEPOINT_LOAD(0x5, &(0x7f0000000240)={0x11, 0x4, &(0x7f0000000000)=ANY=[@ANYBLOB="18000000000000000000000000000000850000002a00000095"], &(0x7f00000001c0)='GPL\x00', 0x4, 0x8f, &(0x7f00000002c0)=""/143}, 0x80)
splice(r2, 0x0, r1, 0x0, 0x6, 0x0)
r3 = socket(0x10, 0x3, 0x0)
r4 = socket$packet(0x11, 0x2, 0x300)
ioctl$sock_SIOCGIFINDEX(r4, 0x8933, &(0x7f0000000080)={'ip6tnl0\x00', <r5=>0x0})
sendmsg$nl_route_sched(r3, &(0x7f00000000c0)={0x0, 0x0, &(0x7f0000000240)={&(0x7f0000000280)=@newqdisc={0x150, 0x24, 0x3fe3aa0262d8c583, 0x0, 0x0, {0x0, 0x0, 0x0, r5, {}, {0xffff, 0xffff}}, [@qdisc_kind_options=@q_red={{0x8}, {0x124, 0x2, [@TCA_RED_PARMS={0x14, 0x1, {0x0, 0xffffe8e4}}, @TCA_RED_STAB={0x104, 0x2, "24b0b059d1fc2dae21c3b333d018aa890e5eacebc33f7c16ed0930265218d3fb678f67c95fe3cc098719da52fa1399d57bc8cc74a44a3f4577e1209ecc9289dea747af04a6c6cb3c523e3578be4cc22ef04c66e377afe1fd393ec6034fa6dd3cc2b84a23d3aba376f73a7573ad2f192f75fd3e4323e7a6472aef0ecc164443068e5a84865eabcbd2a3fe1b6341f2c0040e799b00658236ee27c35dae10eefc27dcbab76fec5e5b51b0148ac9c7f449a946b240ec62e91c5d02f97c2dcb26d5670845a6c9d7911523243ece635af8b11b4325359e7b2a5785b6d0922bae7ce37bb8725ab2c850bce6289ae58fcd2b17207589d9ca06fcfd9aad7c64716568615a"}, @TCA_RED_MAX_P={0x8}]}}]}, 0x150}}, 0x0)
socket$inet6_tcp(0xa, 0x1, 0x0)
writev(r1, &(0x7f0000000040)=[{&(0x7f0000000000)='5', 0xfdef}], 0x1)
writev(r1, &(0x7f00000013c0)=[{&(0x7f00000001c0)="f3", 0x1}], 0x1)
dup3(r2, r1, 0x0)
sendmsg$IPSET_CMD_CREATE(r1, &(0x7f00000003c0)={0x0, 0x0, &(0x7f0000000300)={&(0x7f00000000c0)=ANY=[@ANYBLOB="14000000fd0501"], 0x14}}, 0x0)

executing program 0:
r0 = openat$dsp(0xffffffffffffff9c, &(0x7f0000000200), 0x0, 0x0)
ioctl$SNDCTL_DSP_SPEED(r0, 0xc0045002, &(0x7f0000000080)=0x40000001)
ioctl$SNDCTL_DSP_SUBDIVIDE(r0, 0xc0045009, &(0x7f0000000000)=0x1)
ppoll(&(0x7f00000001c0)=[{r0}], 0x1, 0x0, 0x0, 0x0)

executing program 3:
socketpair$nbd(0x1, 0x1, 0x0, &(0x7f00000007c0)={<r0=>0xffffffffffffffff})
ioctl$sock_SIOCETHTOOL(r0, 0x8946, &(0x7f0000000000)={'veth0_to_hsr\x00', &(0x7f0000000040)=@ethtool_perm_addr={0x4b, 0x44, "daf1684742d14158e6f99acdcb772855f138e5140db8f02a98d7bd744b87e35a1817484e8771cc93858cb08ed71c050fe993a7a00e703b38c3fd47c2e647513d3f046132"}})

executing program 2:
mkdirat(0xffffffffffffff9c, &(0x7f00000000c0)='./file0\x00', 0x0)
syz_mount_image$ext4(&(0x7f00000004c0)='ext4\x00', &(0x7f0000001d80)='./file0/../file0\x00', 0x0, &(0x7f0000000240), 0x1, 0x4a9, &(0x7f0000000900)="$eJzs3c1rXOUaAPBnZprP5t5+3Mul7YXbQi/0ftBMPrg0ubpxpS4KYsGNQo3JNMZMMiEzqU0omOquCxeiKIgL9/4DurEriyCudS8upKI1ggrCyJyZSfM1cbBJBnJ+PziZ95z3ZJ73zfC8vPPOyZwAUutc7UcmYiAiPo+IY/XdzSecqz+s3b85WdsyUa1e+S6TnFfbb57a/L2jEbEaEb0R8fTjES9ktsctL6/MThSLhcXGfr4yt5AvL69cnJmbmC5MF+aHxy6Nj48NjY6M71lfb7/+0u3LHz3Z/cFPr927+8YnH9eaNdCo29iPvVTvelec2HDsSEQ8uh/BOiDX6E9fpxvCH1J7/f4SEeeT/D8WueTVBNKgWq1Wf632tKperQKHVjaZA2eygxFRL2ezg4P1Ofxfoz9bLJUr/71WWpqfqs+Vj0dX9tpMsTDUeK9wPLoytf3hpPxgf2TL/mhEMgd+M9eX7A9OlopTBzvUAVsc3ZL/P+bq+Q+khLf8kF7yH9JL/kN6yX9IL/kP6SX/Ib3kP6SX/If0kv+QXvIf0kv+Qyo9dflybas2//996vry0mzp+sWpQnl2cG5pcnCytLgwOF3q+bC95yuWSgvD/4ulG/lKoVzJl5dXrs6VluYrV2fmJqa7o9C1z/0B2nfi7J0vMxGx+v++ZKvpbtTJVTjcqq/UvwMASJ9cpwcgoGMs/UF6eY8P7PAVvZv0tqpYeKiovxcW2EfZTjcA6JgLp33+B2ll/R/Sy/o/pNfmOb7ZAKRRZ9b/gU6y/g/pNdDi/l9/2nDvrqGI+HNEfJHr6mne6ws4DLLfZBrz/wvH/jmwtbY783OyKNAdES+/e+XtGxOVyuJw7fj368cr7zSOj3Si/UC7mnnazGMAIL3W7t+cbG4HGffbx+oXIWyPf6SxNtmbfEbZv5bZdK1CZo+uXVi9FRGndoqfadzvvP7JR/9ablv8k43HTP0pkvYeSe6bfjDxT2+I/48N8c889F8F0uFObfwZ2in/sklOx3r+bR5/Bvbo+ujW4192ffzLtRj/zrYZ48X3Xv26ZfxbEWd2jN+M15vE2hq/1rYLbca/99wzf2tVV32//jw7xW+qlfKVuYV8eXnl4szcxHRhujA/PHZpfHxsaHRkPJ+sUeebK9XbPXLqs7u79b+/Rfzd+l879u82+//L3z999twu8f91fufX/+Qu8fsi4j9txv9h5KvnW9XV4k+16H92l/i1Y6Ntxi+/9URPm6cCAAegvLwyO1EsFhYVFBQU1gudHpmA/fYg6TvdEgAAAAAAAAAAAKBdB3E5caf7CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwGPwWAAD//1Xr0s0=")
r0 = open(&(0x7f0000000100)='./bus\x00', 0x143142, 0x0)
write$cgroup_freezer_state(r0, &(0x7f00000001c0)='THAWED\x00', 0x7)
r1 = open(&(0x7f0000000180)='./bus\x00', 0x14d27e, 0x0)
mmap(&(0x7f0000000000/0x600000)=nil, 0x600000, 0x27fffff, 0x4002011, r1, 0x0)
fallocate(r1, 0x0, 0x0, 0x1000f4)
r2 = open(&(0x7f0000000080)='./bus\x00', 0x145842, 0x0)
fallocate(r2, 0x3, 0x0, 0x8000)
prctl$PR_GET_NAME(0x10, &(0x7f0000000bc0)=""/4096)

executing program 3:
r0 = socket$inet6(0xa, 0x2, 0x0)
sendmsg$nl_route(0xffffffffffffffff, &(0x7f0000000000)={0x0, 0x0, &(0x7f0000000080)={&(0x7f0000000040)=@bridge_setlink={0x24, 0x13, 0x0, 0x0, 0x0, {}, [@IFLA_AF_SPEC={0x4}]}, 0x24}}, 0x0)
bind$inet6(r0, &(0x7f0000f5dfe4)={0xa, 0x4e20, 0x0, @empty}, 0x1c)
recvmmsg(r0, &(0x7f0000000040), 0x400000000000284, 0x2b, 0x0)
setsockopt$inet6_int(r0, 0x29, 0x2, &(0x7f00000000c0)=0x1bc6, 0x4)
sendto$inet6(r0, 0x0, 0x0, 0x0, &(0x7f0000000300)={0xa, 0x4e20, 0x0, @mcast1}, 0x1c)

[  643.285717][T16494] loop2: detected capacity change from 0 to 512
[  643.325102][T16494] EXT4-fs (loop2): mounted filesystem 00000000-0000-0000-0000-000000000000 r/w without journal. Quota mode: writeback.
[  643.341570][T16494] ext4 filesystem being mounted at /root/syzkaller-testdir440857763/syzkaller.Ihi0LS/100/file0 supports timestamps until 2038-01-19 (0x7fffffff)
[  643.388640][   T57] usb 2-1: USB disconnect, device number 19
executing program 3:
prlimit64(0x0, 0xe, &(0x7f0000000140)={0x8, 0x8b}, 0x0)
sched_setscheduler(0x0, 0x1, &(0x7f0000000080)=0x7)
r0 = getpid()
sched_setscheduler(r0, 0x2, &(0x7f0000000200)=0x4)
mmap(&(0x7f0000000000/0xb36000)=nil, 0xb36000, 0xb635773f06ebbeee, 0x8031, 0xffffffffffffffff, 0x0)
socketpair$unix(0x1, 0x2, 0x0, &(0x7f0000000200)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff})
connect$unix(r1, &(0x7f000057eff8)=@abs, 0x6e)
sendmmsg$unix(r2, &(0x7f0000000000), 0x651, 0x0)
recvmmsg(r1, &(0x7f00000000c0), 0x10106, 0x2, 0x0)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f0000000740)={&(0x7f00000006c0)='sched_switch\x00'}, 0x10)
mkdirat(0xffffffffffffff9c, &(0x7f0000000100)='./file0\x00', 0x0)
openat$dir(0xffffffffffffff9c, 0x0, 0x0, 0x0)
ppoll(0x0, 0x0, 0x0, 0x0, 0x0)
openat$vhost_vsock(0xffffffffffffff9c, &(0x7f00000000c0), 0x2, 0x0)
socket$nl_crypto(0x10, 0x3, 0x15)
openat$snapshot(0xffffffffffffff9c, &(0x7f0000000040), 0x24081, 0x0)

executing program 2:
r0 = socket$packet(0x11, 0x2, 0x300)
r1 = socket(0x10, 0x3, 0x0)
r2 = socket$nl_route(0x10, 0x3, 0x0)
r3 = socket(0x10, 0x803, 0x0)
sendmsg$BATADV_CMD_GET_MESH(r3, &(0x7f00000004c0)={0x0, 0x0, &(0x7f0000000480)={0x0, 0x92}}, 0x0)
r4 = socket$inet_udplite(0x2, 0x2, 0x88)
ioctl$F2FS_IOC_MOVE_RANGE(r4, 0xc020f509, &(0x7f0000000000)={r4, 0x9, 0xffffffffffff1634, 0x8})
setsockopt$IPT_SO_SET_REPLACE(r4, 0x0, 0x40, &(0x7f0000001880)=@mangle={'mangle\x00', 0x44, 0x6, 0x3e0, 0x98, 0x130, 0x0, 0x98, 0x280, 0x348, 0x348, 0x348, 0x348, 0x348, 0x6, 0x0, {[{{@ip={@broadcast, @initdev={0xac, 0x1e, 0x0, 0x0}, 0x0, 0x0, 'geneve1\x00', 'ip6gre0\x00'}, 0x0, 0x70, 0x98}, @TTL={0x28}}, {{@ip={@initdev={0xac, 0x1e, 0x0, 0x0}, @multicast2, 0x0, 0x0, 'netpci0\x00', 'netpci0\x00'}, 0x0, 0x70, 0x98}, @TTL={0x28}}, {{@ip={@local, @local, 0x0, 0x0, 'vcan0\x00', 'netpci0\x00', {}, {}, 0x11, 0x0, 0x4c}, 0x0, 0x70, 0x98}, @unspec=@CHECKSUM={0x28}}, {{@ip={@rand_addr, @multicast2, 0x0, 0x0, 'syzkaller0\x00', 'bond0\x00'}, 0x0, 0x70, 0xb8}, @common=@unspec=@IDLETIMER={0x48, 'IDLETIMER\x00', 0x0, {0x0, 'syz1\x00'}}}, {{@ip={@broadcast, @rand_addr, 0x0, 0x0, 'ip6erspan0\x00', 'team_slave_1\x00'}, 0x0, 0xa0, 0xc8, 0x0, {}, [@common=@inet=@dccp={{0x30}}]}, @TTL={0x28}}], {{'\x00', 0x0, 0x70, 0x98}, {0x28}}}}, 0x440)
socket(0x11, 0x800000003, 0x0)
r5 = socket(0x10, 0x3, 0x0)
sendmsg$nl_route_sched(r5, &(0x7f0000000200)={0x0, 0x0, &(0x7f00000002c0)={&(0x7f0000000400)=@newqdisc={0x48, 0x24, 0xf0b, 0x0, 0x0, {0x0, 0x0, 0x0, 0x0, {}, {0xfff1, 0xffff}}, [@qdisc_kind_options=@q_htb={{0x8}, {0x1c, 0x2, [@TCA_HTB_INIT={0x18}]}}]}, 0x48}}, 0x0)
r6 = syz_genetlink_get_family_id$nl80211(&(0x7f0000000500), r1)
sendmsg$NL80211_CMD_STOP_AP(r3, &(0x7f00000005c0)={&(0x7f0000000080)={0x10, 0x0, 0x0, 0x10}, 0xc, &(0x7f0000000580)={&(0x7f0000000540)={0x1c, r6, 0x800, 0x70bd2b, 0x25dfdbfe, {{}, {@val={0x8}, @void}}, ["", "", "", "", "", ""]}, 0x1c}, 0x1, 0x0, 0x0, 0x40}, 0x30048000)
ioctl$sock_ipv4_tunnel_SIOCADDTUNNEL(r4, 0x89f2, &(0x7f0000000300)={'ip_vti0\x00', &(0x7f0000000800)})
ioctl$sock_ipv6_tunnel_SIOCCHGTUNNEL(0xffffffffffffffff, 0x89f3, &(0x7f0000000340)={'ip6_vti0\x00', &(0x7f0000000240)={'syztnl0\x00', <r7=>0x0, 0x2f, 0x2b, 0xa1, 0x80000000, 0x7a, @mcast2, @private0={0xfc, 0x0, '\x00', 0x1}, 0x7, 0x80, 0x7, 0x7}})
sendmsg$ETHTOOL_MSG_DEBUG_GET(0xffffffffffffffff, &(0x7f00000003c0)={&(0x7f0000000000)={0x10, 0x0, 0x0, 0x40000}, 0xc, &(0x7f0000000380)={&(0x7f0000000640)={0xa4, 0x0, 0x4f3ec79b6c2060a7, 0x70bd29, 0x25dfdbff, {}, [@HEADER={0x48, 0x1, 0x0, 0x1, [@ETHTOOL_A_HEADER_DEV_INDEX={0x8}, @ETHTOOL_A_HEADER_DEV_INDEX={0x8}, @ETHTOOL_A_HEADER_FLAGS={0x8, 0x3, 0x3}, @ETHTOOL_A_HEADER_FLAGS={0x8, 0x3, 0x3}, @ETHTOOL_A_HEADER_DEV_INDEX={0x8}, @ETHTOOL_A_HEADER_DEV_NAME={0x14, 0x2, 'nr0\x00'}, @ETHTOOL_A_HEADER_DEV_INDEX={0x8}]}, @HEADER={0x4}, @HEADER={0x30, 0x1, 0x0, 0x1, [@ETHTOOL_A_HEADER_DEV_INDEX={0x8, 0x1, r7}, @ETHTOOL_A_HEADER_DEV_NAME={0x14, 0x2, 'ip6gretap0\x00'}, @ETHTOOL_A_HEADER_FLAGS={0x8, 0x3, 0x2}, @ETHTOOL_A_HEADER_FLAGS={0x8, 0x3, 0x1}]}, @HEADER={0x14, 0x1, 0x0, 0x1, [@ETHTOOL_A_HEADER_DEV_INDEX={0x8}, @ETHTOOL_A_HEADER_FLAGS={0x8}]}]}, 0xa4}}, 0x4000011)
sendmsg$nl_route(0xffffffffffffffff, &(0x7f00000002c0)={&(0x7f0000000180)={0x10, 0x0, 0x0, 0x200}, 0xc, &(0x7f00000001c0)={&(0x7f0000000240)=@ipv6_getaddrlabel={0x58, 0x4a, 0x2, 0x70bd29, 0x25dfdbfd, {0xa, 0x0, 0x40, 0x0, 0x0, 0x5}, [@IFAL_ADDRESS={0x14, 0x1, @mcast1}, @IFAL_ADDRESS={0x14, 0x1, @private2={0xfc, 0x2, '\x00', 0x1}}, @IFAL_ADDRESS={0x14, 0x1, @remote}]}, 0x58}}, 0x0)
getsockname$packet(r3, &(0x7f0000000100)={0x11, 0x0, <r8=>0x0, 0x1, 0x0, 0x6, @broadcast}, &(0x7f0000000200)=0x14)
sendmsg$nl_route(r2, &(0x7f0000000000)={0x0, 0x0, &(0x7f0000000140)={&(0x7f0000000040)=ANY=[@ANYBLOB="3c0000001000010400eeffffffffffffff000000", @ANYRES32=r8, @ANYBLOB="01000000010000001c0012000c000100627269646765"], 0x3c}}, 0x0)
sendmsg$nl_route_sched(r1, &(0x7f00000007c0)={0x0, 0x0, &(0x7f00000000c0)={&(0x7f0000000740)=@newqdisc={0x70, 0x24, 0xe0b, 0x0, 0x0, {0x0, 0x0, 0x0, r8, {}, {0xffff, 0xffff}}, [@qdisc_kind_options=@q_netem={{0xa}, {0x40, 0x2, {{}, [@TCA_NETEM_LOSS={0x1c, 0x5, 0x0, 0x1, [@NETEM_LOSS_GI={0x18, 0x1, {0x0, 0x0, 0x0, 0xfffff062}}]}, @TCA_NETEM_ECN={0x8, 0x7, 0x1}]}}}]}, 0x70}}, 0x0)
sendto$packet(r0, 0x0, 0x0, 0x0, &(0x7f0000000040)={0x11, 0x8100, r8, 0x1, 0x0, 0x6, @multicast}, 0x14)

executing program 1:
r0 = syz_io_uring_setup(0x239, &(0x7f0000000080)={0x0, 0x0, 0x10100}, &(0x7f0000000000), &(0x7f00000001c0))
ioctl$AUTOFS_DEV_IOCTL_REQUESTER(0xffffffffffffffff, 0xc018937b, &(0x7f0000000040)={{0x1, 0x1, 0x18, <r1=>r0, {0xffffffffffffffff, 0xffffffffffffffff}}, './file0\x00'})
bpf$MAP_CREATE(0x0, &(0x7f00000000c0)=@bloom_filter={0x1e, 0x7, 0xe1, 0xfffffffe, 0x400, 0xffffffffffffffff, 0x3f, '\x00', 0x0, r1, 0x3, 0x3, 0x3, 0x6}, 0x48)
bpf$BPF_PROG_TEST_RUN(0xa, &(0x7f0000000240)={0xffffffffffffffff, 0xfca804a0, 0x6, 0x8, &(0x7f00000002c0)="b80000050000", &(0x7f0000000300)=""/8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x50)
io_uring_register$IORING_REGISTER_PERSONALITY(r0, 0x9, 0x0, 0x0)
syz_io_uring_setup(0x6b68, &(0x7f0000000140)={0x0, 0x3681, 0x20, 0x3, 0x3dc, 0x0, r1}, &(0x7f0000000200), &(0x7f0000000400))
r2 = openat$sysfs(0xffffffffffffff9c, &(0x7f0000000640)='/sys/power/pm_test', 0x42, 0x0)
io_setup(0x20, &(0x7f0000001140)=<r3=>0x0)
socket$unix(0x1, 0x0, 0x0)
io_submit(r3, 0x1, &(0x7f00000001c0)=[&(0x7f0000002040)={0xf, 0x400000000000, 0x0, 0x1, 0x0, r2, &(0x7f0000000080)="0d32818e7e6ae0cd", 0x8}])

executing program 4:
r0 = syz_open_dev$dri(&(0x7f0000001700), 0x0, 0x0)
ioctl$DRM_IOCTL_SYNCOBJ_RESET(r0, 0xc01064c4, &(0x7f0000001880)={0x0})

[  643.915579][T14884] EXT4-fs (loop2): unmounting filesystem 00000000-0000-0000-0000-000000000000.
executing program 0:
r0 = openat$binderfs(0xffffffffffffff9c, &(0x7f0000000040)='./binderfs/binder0\x00', 0x0, 0x0)
ioctl$BINDER_GET_EXTENDED_ERROR(r0, 0xc018620b, &(0x7f0000001340))

executing program 4:
syz_mount_image$exfat(&(0x7f0000000180), &(0x7f0000000000)='./file0\x00', 0x0, &(0x7f0000000600)=ANY=[], 0x85, 0x14ff, &(0x7f0000000980)="$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")

executing program 0:
r0 = socket(0x10, 0x803, 0x0)
sendto(r0, &(0x7f00000000c0)="120000001200e7ef007b00000000000000a1", 0x12, 0x0, 0x0, 0x0)
sendmsg$ETHTOOL_MSG_COALESCE_SET(0xffffffffffffffff, &(0x7f0000000540)={0x0, 0x0, &(0x7f0000000500)={0x0, 0x4c}}, 0x0)
recvmmsg(r0, &(0x7f00000037c0)=[{{&(0x7f00000004c0)=@ethernet={0x0, @random}, 0xfdf4, &(0x7f0000000380)=[{&(0x7f0000000140)=""/100, 0x308}, {&(0x7f0000000280)=""/85, 0x7c}, {&(0x7f0000000fc0)=""/4096, 0x197}, {&(0x7f0000000400)=""/106, 0x645}, {&(0x7f0000000980)=""/73, 0x1b}, {&(0x7f0000000200)=""/77, 0xf0}, {&(0x7f00000007c0)=""/154, 0x85}, {&(0x7f00000001c0)=""/17, 0x1d8}], 0x21, &(0x7f0000000600)=""/191, 0x41}}], 0x4000000000003b4, 0x0, &(0x7f0000003700)={0x77359400})

[  644.368788][T16511] random: crng reseeded on system resumption
executing program 3:
r0 = bpf$PROG_LOAD(0x5, &(0x7f00000004c0)={0x6, 0xb, &(0x7f0000000240)=ANY=[@ANYBLOB="18000000000000e50000000000000000180100002020702500000000002020207b1af8ff00000000bfa100000000000007010000f8ffffffb702000008000000b70300001e334185850000007300000095"], &(0x7f00000000c0)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_PROG_TEST_RUN(0xa, &(0x7f0000000640)={r0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2}, 0x50)

[  645.310537][T16513] loop4: detected capacity change from 0 to 256
executing program 1:
syz_mount_image$udf(&(0x7f00000000c0), &(0x7f0000000180)='./file0\x00', 0x2000002, &(0x7f00000004c0)={[{@volume={'volume', 0x3d, 0x3e}}, {@gid}, {@uid_forget}, {@iocharset={'iocharset', 0x3d, 'macromanian'}}, {@gid}, {}, {@gid_ignore}, {@lastblock}, {@iocharset={'iocharset', 0x3d, 'cp850'}}]}, 0x1, 0xc32, &(0x7f0000000e00)="$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")
openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000080)='cpuset.effective_mems\x00', 0x275a, 0x0)

[  645.402346][T16517] xt_CHECKSUM: CHECKSUM should be avoided.  If really needed, restrict with "-p udp" and only use in OUTPUT
executing program 0:
r0 = socket$nl_generic(0x10, 0x3, 0x10)
r1 = syz_genetlink_get_family_id$nl80211(&(0x7f00000001c0), 0xffffffffffffffff)
r2 = socket$nl_generic(0x10, 0x3, 0x10)
ioctl$sock_SIOCGIFINDEX_80211(r0, 0x8933, &(0x7f0000000cc0)={'wlan0\x00', <r3=>0x0})
sendmsg$NL80211_CMD_NEW_INTERFACE(r2, &(0x7f0000000e40)={0x0, 0x0, &(0x7f0000000e00)={&(0x7f0000000080)=ANY=[@ANYBLOB='T\x00\x00\x00', @ANYRES16=r1, @ANYBLOB="250900000000000000000700000208000300", @ANYRES32=r3, @ANYBLOB="1400060064756d6d7930000000000000000000001400040076657468315f746f5f626f01640000000500530001"], 0x54}}, 0x0)

[  645.443402][T16513] exFAT-fs (loop4): failed to load upcase table (idx : 0x0001023f, chksum : 0x5c87467f, utbl_chksum : 0xe619d30d)
[  645.507641][T16519] loop1: detected capacity change from 0 to 2048
[  645.514931][T16513] exFAT-fs (loop4): failed to load alloc-bitmap
[  645.521222][T16513] exFAT-fs (loop4): failed to recognize exfat type
[  645.563416][T16519] UDF-fs: INFO Mounting volume 'LiuxUDF', timestamp 2022/11/22 14:59 (1000)
executing program 2:
r0 = socket$inet_tcp(0x2, 0x1, 0x0)
setsockopt$EBT_SO_SET_ENTRIES(r0, 0x0, 0x80, &(0x7f00000000c0)=@nat={'nat\x00', 0x19, 0x1, 0x178, [0x200003c0, 0x0, 0x0, 0x200003f0, 0x20000420], 0x0, 0x0, &(0x7f00000003c0)=ANY=[@ANYBLOB="000000000000f8ffffff000000000000000000000000000000000000000000000000000000000000feffffff00000000000000000000000000000000000000f00c0000000000000000000000000000000000000000000000ffffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000feffffff01000000050000000000000008006966623000000000000000000000000064756d6d79300000000000000000000069705f76746930000000000000000000697036746e6c30000000000000000000aaaaaaaaaabb0400000000000182c20000000000000000000000b8000000b8000000e80000006970000000000000000000000000000000000000000000a823c565625b8d720020000000000000007f00004dab14140000000000000000000084200400000000000000000000000041554449540000bcb92dfff07fca0000004600f58f5dc8438b000000000000000800"/376]}, 0x1f0)
r1 = socket(0x200000000000011, 0x2, 0x0)
ioctl$sock_SIOCGIFINDEX(r1, 0x8933, &(0x7f0000000000)={'bridge0\x00', <r2=>0x0})
bind$packet(r1, &(0x7f0000000180)={0x11, 0x0, r2}, 0x14)
getsockname$packet(r1, &(0x7f0000000080)={0x11, 0x0, <r3=>0x0, 0x1, 0x0, 0x6, @broadcast}, &(0x7f00000001c0)=0x14)
sendto$packet(r1, 0x0, 0x0, 0x0, &(0x7f00000015c0)={0x11, 0x0, r3, 0x1, 0x0, 0x6, @remote}, 0x14)

executing program 3:
bpf$ENABLE_STATS(0x20, 0x0, 0x0)
r0 = bpf$MAP_CREATE_RINGBUF(0x0, &(0x7f00000009c0)={0x1b, 0x0, 0x0, 0x40000, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0}, 0x48)
r1 = bpf$PROG_LOAD(0x5, &(0x7f0000000b00)={0x11, 0xf, &(0x7f0000000340)=ANY=[@ANYBLOB="1800000000000000000000000000000018110000", @ANYRES32=r0, @ANYBLOB="0000000000000000b702000014000000b703000000b700008500000083000000bf0900000000000055090100000000009500000000000000bf91000000000000b7020000000000008500000085000000b70000000000000095"], &(0x7f0000000080)='syzkaller\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f0000000040)={&(0x7f0000000000)='percpu_alloc_percpu\x00', r1}, 0x10)
bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x0, 0xc, 0x0, &(0x7f0000000240)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)

executing program 1:
r0 = socket$inet_tcp(0x2, 0x1, 0x0)
setsockopt$EBT_SO_SET_ENTRIES(r0, 0x0, 0x80, &(0x7f00000000c0)=@nat={'nat\x00', 0x19, 0x1, 0x178, [0x200003c0, 0x0, 0x0, 0x200003f0, 0x20000420], 0x0, 0x0, &(0x7f00000003c0)=ANY=[@ANYBLOB="000000000000f8ffffff000000000000000000000000000000000000000000000000000000000000feffffff00000000000000000000000000000000000000f00c0000000000000000000000000000000000000000000000ffffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000feffffff01000000050000000000000008006966623000000000000000000000000064756d6d79300000000000000000000069705f76746930000000000000000000697036746e6c30000000000000000000aaaaaaaaaabb0400000000000182c20000000000000000000000b8000000b8000000e80000006970000000000000000000000000000000000000000000a823c565625b8d720020000000000000007f00004dab14140000000000000000000084200400000000000000000000000041554449540000bcb92dfff07fca0000004600f58f5dc8438b000000000000000800"/376]}, 0x1f0)
r1 = socket(0x200000000000011, 0x2, 0x0)
ioctl$sock_SIOCGIFINDEX(r1, 0x8933, &(0x7f0000000000)={'bridge0\x00', <r2=>0x0})
bind$packet(r1, &(0x7f0000000180)={0x11, 0x0, r2}, 0x14)
getsockname$packet(r1, &(0x7f0000000080)={0x11, 0x0, <r3=>0x0, 0x1, 0x0, 0x6, @broadcast}, &(0x7f00000001c0)=0x14)
sendto$packet(r1, 0x0, 0x0, 0x0, &(0x7f00000015c0)={0x11, 0x0, r3, 0x1, 0x0, 0x6, @remote}, 0x14)

executing program 4:
syz_emit_ethernet(0x7e, &(0x7f0000000840)={@multicast, @remote, @void, {@ipv6={0x86dd, @icmpv6={0x0, 0x6, "122d92", 0x48, 0x3a, 0x0, @remote, @mcast2, {[], @pkt_toobig={0x2, 0x0, 0x0, 0x0, {0x0, 0x6, "98cec1", 0x0, 0x0, 0x0, @loopback, @empty, [@hopopts={0x11, 0x0, '\x00', [@pad1]}, @fragment={0x3c}]}}}}}}}, 0x0)

executing program 0:
r0 = openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000080)='cgroup.controllers\x00', 0x275a, 0x0)
r1 = openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000080)='cgroup.controllers\x00', 0x275a, 0x0)
write$binfmt_script(r1, &(0x7f0000000140), 0xfea7)
ioctl$FS_IOC_RESVSP(r1, 0x40305839, &(0x7f0000000000)={0x0, 0x0, 0xefff, 0xfa64})
ioctl$FS_IOC_RESVSP(r0, 0x40305828, &(0x7f00000000c0)={0x0, 0x0, 0x0, 0x7})
ioctl$FS_IOC_RESVSP(r1, 0x40305829, &(0x7f0000000040)={0x0, 0x0, 0xc000, 0x80000003})
ioctl$FS_IOC_RESVSP(r1, 0x40305828, &(0x7f00000001c0)={0x0, 0x1, 0x0, 0x1ff})

executing program 2:
openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000240)='cgroup.controllers\x00', 0x26e1, 0x0)
bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x0, 0xc, &(0x7f0000000440)=ANY=[@ANYBLOB="1800000000000000000000000000000018110000", @ANYRES32, @ANYBLOB="0000000000000000b70800000d0000007b8af8ff00000000bfa200000000000007020000f8ffffffb703000008000000b704000000000000850000000100000095"], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
r0 = bpf$MAP_CREATE(0x0, &(0x7f0000000180)=@base={0xb, 0x5, 0x5, 0x9, 0x1}, 0x48)
bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x0, 0xc, &(0x7f0000000440)=ANY=[@ANYBLOB="1800000000000000000000000000000018110000", @ANYRES32, @ANYBLOB="0000000000000000b708000008"], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$PROG_LOAD(0x5, &(0x7f0000000340)={0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$MAP_GET_NEXT_KEY(0x2, &(0x7f00000004c0)={r0, &(0x7f0000000340), &(0x7f00000005c0)=""/155}, 0x20)
bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x0, 0x0, &(0x7f0000000440)=ANY=[@ANYBLOB="1800000000800000000000000000000018110000", @ANYRES32=r0], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
r1 = bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x11, 0xc, &(0x7f0000000440)=ANY=[], &(0x7f0000000240)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f0000000340)={&(0x7f0000000300)='ext4_ext_remove_space_done\x00', r1}, 0x10)
openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000000)='cgroup.controllers\x00', 0x275a, 0x0)

executing program 4:
r0 = socket$inet(0x2, 0x4000000000000001, 0x0)
setsockopt$inet_tcp_TCP_MD5SIG(r0, 0x6, 0xe, &(0x7f00000004c0)={@in={{0x2, 0x0, @loopback}}, 0x0, 0x0, 0x7, 0x0, "98d3340600c7aa11897ecaab876eab79576839c5656be8410f2802e944af80373be2666b665770173fbd1883303b6ac4749393ad08f139a68f00"}, 0xd8)
bind$inet(r0, &(0x7f0000000480)={0x2, 0x4e23, @multicast1}, 0x10)
sendto$inet(r0, 0x0, 0x0, 0x200007fd, &(0x7f0000000000)={0x2, 0x24e23, @loopback}, 0x10)
write$binfmt_elf64(r0, &(0x7f00000000c0)=ANY=[], 0xc63b9e35)
sendmsg$IPCTNL_MSG_TIMEOUT_DEFAULT_GET(r0, &(0x7f0000000440)={0x0, 0x0, &(0x7f0000000300)={&(0x7f0000000380)={0x14}, 0x14}}, 0x48885)
ioctl$FS_IOC_ADD_ENCRYPTION_KEY(0xffffffffffffffff, 0xc0406618, 0x0)

executing program 1:
syz_emit_vhci(&(0x7f0000001740)=@HCI_EVENT_PKT={0x4, @hci_ev_role_change={{0x12, 0x8}, {0x0, @fixed={'\xaa\xaa\xaa\xaa\xaa', 0x10}}}}, 0xb)

executing program 2:
prlimit64(0x0, 0xe, &(0x7f0000000140)={0x8, 0x8b}, 0x0)
sched_setscheduler(0x0, 0x1, &(0x7f0000000080)=0x7)
r0 = getpid()
sched_setaffinity(0x0, 0x8, &(0x7f00000002c0)=0x2)
sched_setscheduler(r0, 0x2, &(0x7f0000000200)=0x4)
mmap(&(0x7f0000000000/0xb36000)=nil, 0xb36000, 0xb635773f06ebbeee, 0x8031, 0xffffffffffffffff, 0x0)
socketpair$unix(0x1, 0x3, 0x0, &(0x7f0000000380)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff})
connect$unix(r1, &(0x7f00000003c0)=@abs, 0x6e)
sendmmsg$unix(r2, &(0x7f0000000000), 0x651, 0x0)
recvmmsg(r1, &(0x7f00000000c0), 0x10106, 0x2, 0x0)
r3 = bpf$MAP_CREATE(0x0, &(0x7f00000000c0)=@base={0x1b, 0x0, 0x0, 0x8000}, 0x48)
bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x0, 0xc, &(0x7f0000000240)=ANY=[@ANYBLOB="1800000000000000000000000000000018120000", @ANYRES32=r3, @ANYBLOB="0000000000000000b7080000000000007b8af8ff00000000bfa200000000000007020000f8ffffffb703000008000000b704000002010000850000004300000095"], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
r4 = bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x11, 0xc, &(0x7f0000000240)=ANY=[], &(0x7f0000000200)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f0000000300)={&(0x7f0000000000)='sched_switch\x00', r4}, 0x10)
mkdirat(0xffffffffffffff9c, &(0x7f0000000000)='./file0\x00', 0x0)
bpf$MAP_CREATE(0x0, &(0x7f0000000640)=@base={0x17, 0x0, 0x4, 0x0, 0x0, 0x1}, 0x48)
io_setup(0x3ff, &(0x7f0000000500))
io_submit(0x0, 0x0, 0x0)
bpf$PROG_LOAD_XDP(0x5, 0x0, 0x0)
pipe2$9p(&(0x7f0000000240)={<r5=>0xffffffffffffffff}, 0x0)
dup(0xffffffffffffffff)
mount$9p_fd(0x0, &(0x7f0000000040)='./file0\x00', &(0x7f0000000b80), 0x0, &(0x7f0000000300)=ANY=[@ANYBLOB='trans=fd,rfdno=', @ANYRESHEX=r5])

executing program 0:
bpf$BPF_LINK_CREATE(0x1c, 0x0, 0x0)
r0 = socket$inet6(0xa, 0x3, 0x7)
connect$inet6(r0, &(0x7f00000000c0)={0xa, 0x0, 0x0, @loopback}, 0x1c)
prlimit64(0x0, 0xe, &(0x7f0000000140)={0x8, 0x100008b}, 0x0)
sched_setscheduler(0x0, 0x1, &(0x7f0000000080)=0x7)
r1 = getpid()
sched_setscheduler(r1, 0x1, &(0x7f0000000100)=0x5)
mmap(&(0x7f0000000000/0xb36000)=nil, 0xb36000, 0xb635773f06ebbeee, 0x10, 0xffffffffffffffff, 0x0)
socketpair$unix(0x1, 0x3, 0x0, &(0x7f0000000240)={<r2=>0xffffffffffffffff, <r3=>0xffffffffffffffff})
connect$unix(r2, &(0x7f000057eff8)=@abs, 0x6e)
sendmmsg$unix(r3, &(0x7f00000bd000), 0x318, 0x0)
recvmmsg(r2, &(0x7f00000000c0), 0x10106, 0x2, 0x0)
sendmmsg(r0, &(0x7f0000000480), 0x2e9, 0xfc00)

executing program 1:
timer_create(0x0, 0x0, &(0x7f0000000140))
r0 = syz_open_procfs(0x0, &(0x7f0000000000)='timers\x00')
preadv(r0, &(0x7f0000000580)=[{&(0x7f0000000200)=""/122, 0x7a}], 0x1, 0x45, 0x0)

[  647.473102][T16549] 9pnet_fd: Insufficient options for proto=fd
executing program 0:
close_range(0xffffffffffffffff, 0xffffffffffffffff, 0x2)
r0 = bpf$PROG_LOAD(0x5, &(0x7f000000e000)={0xe, 0x4, &(0x7f0000000540)=ANY=[@ANYBLOB="b4050000200080006110600000000000c60000000000000095000000000000009f33ef60916e6e893f1eeb0be2566cd0723043c47c896ce0bce66a245ad99b817fd98cd824498949714ffaac8a6f77ef26dcca5582054d54d50600000000000000bdae214fa68a0557eb3c5ca683a4b6fc89398f2b9000f224891060017cfa6fa26fa7a34700458c60897d4a6148a1c11428607c40de60beac671e8e8fdecb03588aa623fa71f871ab5c2ff8007d6002084e5b52710aeee835cf0d78e45f70983826fb8579c1fb01d2c5553d2ccb5fc5b51fe6b174ebd9907dcff414ed55b0d10cdbe7009a6fe7cc78762f1d48cdbca64920db9a50f86c21632fd30bf05121438bb74e4670ab5dfe447a4bd344e0bd74ff05d37e2bb8675a432fc48fefda5b1037b2a3f68e3b9db863c7585514414bb426e1230bc1cd4c02c499cccd73c5339c4ff04760ceb44276e9bd94d1c2e6d17dc5c2edf332a62f5fe68fbbbbfcfd78a9f3fdc1f50c445e3f30e703cf05b90fbf940e6652b7df1521d5f816f66ac3027460ae991e7f834dd7a7fc2a7003d1a6cf5478533584961c329fcf4fed5c9455640dcd28273dc9753c76c5b9081661491266df22a9cf60acc97911572915a3019c3ca60ec53bb1130c2d27fed7d67c440e23d130e51eea1e085bebabe7059de9cbfc51179d665ec1ecdf01439e9961d657c0bc127c0cf8169b892345a603185b029abc20040000004030b67bc76013863bb3f43de657cdacd723e777e61ee5653b4e6d6c6a53fcab6a49fdf800685736df8e12a051a6f64e0443873bf399156f23c8b539d88199d20f46fa80ce8f0515b6ff65cf019a"], &(0x7f0000003ff6)='GPL\x00', 0x4, 0xfd90, &(0x7f000000cf3d)=""/195, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x8, &(0x7f0000000000), 0x366, 0x10, &(0x7f0000000000), 0x1dd}, 0x48)
r1 = bpf$PROG_LOAD(0x5, &(0x7f000000e000)={0xe, 0x4, &(0x7f0000000540)=ANY=[@ANYBLOB="b4050000200080006110600000000000c60000000000000095000000000000009f33ef60916e6e893f1eeb0be2566cd0723043c47c896ce0bce66a245ad99b817fd98cd824498949714ffaac8a6f77ef26dcca5582054d54d50600000000000000bdae214fa68a0557eb3c5ca683a4b6fc89398f2b9000f224891060017cfa6fa26fa7a34700458c60897d4a6148a1c11428607c40de60beac671e8e8fdecb03588aa623fa71f871ab5c2ff8007d6002084e5b52710aeee835cf0d78e45f70983826fb8579c1fb01d2c5553d2ccb5fc5b51fe6b174ebd9907dcff414ed55b0d10cdbe7009a6fe7cc78762f1d48cdbca64920db9a50f86c21632fd30bf05121438bb74e4670ab5dfe447a4bd344e0bd74ff05d37e2bb8675a432fc48fefda5b1037b2a3f68e3b9db863c7585514414bb426e1230bc1cd4c02c499cccd73c5339c4ff04760ceb44276e9bd94d1c2e6d17dc5c2edf332a62f5fe68fbbbbfcfd78a9f3fdc1f50c445e3f30e703cf05b90fbf940e6652b7df1521d5f816f66ac3027460ae991e7f834dd7a7fc2a7003d1a6cf5478533584961c329fcf4fed5c9455640dcd28273dc9753c76c5b9081661491266df22a9cf60acc97911572915a3019c3ca60ec53bb1130c2d27fed7d67c440e23d130e51eea1e085bebabe7059de9cbfc51179d665ec1ecdf01439e9961d657c0bc127c0cf8169b892345a603185b029abc20040000004030b67bc76013863bb3f43de657cdacd723e777e61ee5653b4e6d6c6a53fcab6a49fdf800685736df8e12a051a6f64e0443873bf399156f23c8b539d88199d20f46fa80ce8f0515b6ff65cf019a"], &(0x7f0000003ff6)='GPL\x00', 0x4, 0xfd90, &(0x7f000000cf3d)=""/195, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x8, &(0x7f0000000000), 0x366, 0x10, &(0x7f0000000000), 0x1dd}, 0x48)
r2 = bpf$MAP_CREATE(0x0, &(0x7f0000000200)=@base={0xf, 0x4, 0x4, 0x12}, 0x48)
bpf$BPF_PROG_DETACH(0x8, &(0x7f0000000080)={@map=r2, r1, 0x26}, 0x10)
bpf$BPF_PROG_DETACH(0x8, &(0x7f0000000080)={@map=r2, r0, 0x26}, 0x10)

executing program 3:
r0 = socket(0x10, 0x803, 0x0)
sendto(r0, &(0x7f00000000c0)="120000001200e7ef007b00000000000000a1", 0x12, 0x0, 0x0, 0x0)
sendmsg$sock(0xffffffffffffffff, 0x0, 0x0)
recvmmsg(r0, &(0x7f00000037c0)=[{{&(0x7f00000004c0)=@ethernet={0x0, @random}, 0xfdf4, &(0x7f0000000380)=[{&(0x7f0000000140)=""/100, 0x365}, {&(0x7f0000000280)=""/85, 0x3c}, {&(0x7f0000000fc0)=""/4096, 0x197}, {&(0x7f0000000400)=""/106, 0x645}, {&(0x7f0000000980)=""/73, 0x1b}, {&(0x7f0000000200)=""/77, 0x5dc}, {&(0x7f00000007c0)=""/154, 0x4c}, {&(0x7f00000001c0)=""/17, 0x1d8}], 0x21, &(0x7f0000000600)=""/191, 0x41}}], 0x4000000000003b4, 0x0, &(0x7f0000003700)={0x77359400})

executing program 1:
prlimit64(0x0, 0xe, &(0x7f0000000140)={0x8, 0x8b}, 0x0)
sched_setscheduler(0x0, 0x1, &(0x7f0000000080)=0x7)
r0 = getpid()
sched_setaffinity(0x0, 0x8, &(0x7f00000002c0)=0x2)
sched_setscheduler(r0, 0x2, &(0x7f0000000200)=0x4)
mmap(&(0x7f0000000000/0xb36000)=nil, 0xb36000, 0xb635773f06ebbeee, 0x8031, 0xffffffffffffffff, 0x0)
socketpair$unix(0x1, 0x3, 0x0, &(0x7f0000000380)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff})
connect$unix(r1, &(0x7f00000003c0)=@abs, 0x6e)
sendmmsg$unix(r2, &(0x7f0000000000), 0x651, 0x0)
recvmmsg(r1, &(0x7f00000000c0), 0x10106, 0x2, 0x0)
r3 = bpf$MAP_CREATE(0x0, &(0x7f00000000c0)=@base={0x1b, 0x0, 0x0, 0x8000}, 0x48)
bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x0, 0xc, &(0x7f0000000240)=ANY=[@ANYBLOB="1800000000000000000000000000000018120000", @ANYRES32=r3, @ANYBLOB="0000000000000000b7080000000000007b8af8ff00000000bfa200000000000007020000f8ffffffb703000008000000b704000002010000850000004300000095"], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
r4 = bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x11, 0xc, &(0x7f0000000240)=ANY=[], &(0x7f0000000200)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f0000000300)={&(0x7f0000000000)='sched_switch\x00', r4}, 0x10)
mkdirat(0xffffffffffffff9c, &(0x7f0000000000)='./file0\x00', 0x0)
bpf$MAP_CREATE(0x0, &(0x7f0000000640)=@base={0x17, 0x0, 0x4, 0x0, 0x0, 0x1}, 0x48)
io_setup(0x3ff, &(0x7f0000000500))
io_submit(0x0, 0x0, 0x0)
bpf$PROG_LOAD_XDP(0x5, 0x0, 0x0)
pipe2$9p(&(0x7f0000000240)={<r5=>0xffffffffffffffff}, 0x0)
dup(0xffffffffffffffff)
mount$9p_fd(0x0, &(0x7f0000000040)='./file0\x00', &(0x7f0000000b80), 0x0, &(0x7f0000000300)=ANY=[@ANYBLOB='trans=fd,rfdno=', @ANYRESHEX=r5])

executing program 4:
r0 = socket$kcm(0x10, 0x2, 0x10)
sendmsg$kcm(r0, &(0x7f00000000c0)={0x0, 0x0, &(0x7f0000000480)=[{&(0x7f0000000000)="1400000010003507d25a806f8c6394f90324fc60", 0x14}], 0x1}, 0x0)
recvmsg$kcm(r0, &(0x7f0000006440)={0x0, 0x0, 0x0}, 0x0)
recvmsg$kcm(r0, &(0x7f0000000380)={0x0, 0x0, &(0x7f00000027c0)=[{&(0x7f0000000500)=""/4096, 0x500}, {&(0x7f0000001500)=""/4082, 0xff2}], 0x2}, 0x0)

executing program 2:
syz_mount_image$udf(&(0x7f00000000c0), &(0x7f0000000180)='./file0\x00', 0x2000002, &(0x7f00000004c0)={[{@volume={'volume', 0x3d, 0x3e}}, {@gid}, {@uid_forget}, {@iocharset={'iocharset', 0x3d, 'macromanian'}}, {@gid}, {}, {@gid_ignore}, {@lastblock}, {@iocharset={'iocharset', 0x3d, 'cp850'}}]}, 0x1, 0xc32, &(0x7f0000000e00)="$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")
openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000080)='cpuset.effective_mems\x00', 0x275a, 0x0)

[  648.738051][T16561] 9pnet_fd: Insufficient options for proto=fd
executing program 0:
unlink(&(0x7f0000000000)='./file1\x00')
rename(&(0x7f0000000040)='./file0\x00', &(0x7f0000000080)='./file1\x00')
openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000040)='blkio.bfq.io_merged\x00', 0x275a, 0x0)
renameat2(0xffffffffffffff9c, &(0x7f00000000c0)='./file3\x00', 0xffffffffffffff9c, &(0x7f00000007c0)='./file7\x00', 0x0)
openat(0xffffffffffffff9c, &(0x7f0000000080)='./bus\x00', 0x183341, 0x0)
rename(&(0x7f0000000240)='./bus\x00', &(0x7f0000000180)='./file0\x00')

executing program 3:
syz_emit_ethernet(0x7e, &(0x7f0000000840)={@multicast, @remote, @void, {@ipv6={0x86dd, @icmpv6={0x0, 0x6, "122d92", 0x48, 0x3a, 0x0, @remote, @mcast2, {[], @pkt_toobig={0x2, 0x0, 0x0, 0x0, {0x0, 0x6, "98cec1", 0x0, 0x0, 0x0, @loopback, @empty, [@hopopts={0x11, 0x0, '\x00', [@pad1]}, @fragment={0x3c}]}}}}}}}, 0x0)

executing program 4:
r0 = bpf$MAP_CREATE(0x0, &(0x7f00000009c0)=@base={0xa, 0x4, 0xfff, 0x7}, 0x48)
bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x0, 0xc, &(0x7f0000000440)=ANY=[@ANYBLOB="1800000000000000000000000000000018110000", @ANYRES32=r0, @ANYBLOB="0000000000000000b7080000000000007b8af8ff00000000bfa200000000000007020000f8ffffffb7030000080000002d01000000000000850000000100000095"], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$MAP_UPDATE_CONST_STR(0x2, &(0x7f0000001ac0)={{r0}, &(0x7f0000001a40), &(0x7f0000001a80)='%+9llu \x00'}, 0x20)
r1 = bpf$PROG_LOAD(0x5, &(0x7f00000008c0)={0x6, 0xc, &(0x7f0000000440)=ANY=[], &(0x7f0000000240)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_PROG_TEST_RUN(0xa, &(0x7f0000000340)={r1, 0xf, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x50)

[  649.414161][T16563] loop2: detected capacity change from 0 to 2048
executing program 4:
prctl$PR_SCHED_CORE(0x3e, 0x1, 0x0, 0x2, 0x0)
sched_setaffinity(0x0, 0x8, &(0x7f0000000040)=0x10001)
r0 = openat$hwrng(0xffffffffffffff9c, &(0x7f0000000000), 0x0, 0x0)
preadv(r0, &(0x7f0000000240)=[{&(0x7f000001aa80)=""/102386, 0x18ff2}], 0x1, 0x0, 0x0)
r1 = socket(0x840000000002, 0x3, 0x100)
connect$inet(r1, &(0x7f00000005c0)={0x2, 0x0, @local}, 0x10)
sendmmsg$inet(r1, &(0x7f0000005240)=[{{0x0, 0x0, 0x0}, 0xfffffdef}], 0x4000095, 0x0)

executing program 1:
r0 = socket(0x1e, 0x4, 0x0)
r1 = socket$inet6_icmp_raw(0xa, 0x3, 0x3a)
ioctl$ifreq_SIOCGIFINDEX_vcan(r0, 0x8933, &(0x7f0000000140)={'vcan0\x00', <r2=>0x0})
ioctl$sock_inet6_SIOCSIFADDR(r1, 0x8916, &(0x7f0000000180)={@rand_addr=' \x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01', 0x0, r2})

executing program 3:
openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000240)='cgroup.controllers\x00', 0x26e1, 0x0)
bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x0, 0xc, &(0x7f0000000440)=ANY=[@ANYBLOB="1800000000000000000000000000000018110000", @ANYRES32, @ANYBLOB="0000000000000000b70800000d0000007b8af8ff00000000bfa200000000000007020000f8ffffffb703000008000000b704000000000000850000000100000095"], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
r0 = bpf$MAP_CREATE(0x0, &(0x7f0000000180)=@base={0xb, 0x5, 0x5, 0x9, 0x1}, 0x48)
bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x0, 0xc, &(0x7f0000000440)=ANY=[@ANYBLOB="1800000000000000000000000000000018110000", @ANYRES32, @ANYBLOB="0000000000000000b708000008"], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$PROG_LOAD(0x5, &(0x7f0000000340)={0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$MAP_GET_NEXT_KEY(0x2, &(0x7f00000004c0)={r0, &(0x7f0000000340), &(0x7f00000005c0)=""/155}, 0x20)
bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x0, 0x0, &(0x7f0000000440)=ANY=[@ANYBLOB="1800000000800000000000000000000018110000", @ANYRES32=r0], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
r1 = bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x11, 0xc, &(0x7f0000000440)=ANY=[], &(0x7f0000000240)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f0000000340)={&(0x7f0000000300)='ext4_ext_remove_space_done\x00', r1}, 0x10)
openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000000)='cgroup.controllers\x00', 0x275a, 0x0)

[  649.554224][T16563] UDF-fs: INFO Mounting volume 'LiuxUDF', timestamp 2022/11/22 14:59 (1000)
executing program 1:
r0 = socket$nl_generic(0x10, 0x3, 0x10)
r1 = syz_genetlink_get_family_id$ethtool(&(0x7f0000000040), 0xffffffffffffffff)
sendmsg$ETHTOOL_MSG_LINKINFO_SET(r0, &(0x7f0000000180)={0x0, 0x0, &(0x7f0000000140)={&(0x7f00000000c0)={0x34, r1, 0x1, 0x0, 0x0, {}, [@ETHTOOL_A_LINKINFO_TP_MDIX_CTRL={0x5}, @ETHTOOL_A_LINKINFO_HEADER={0x18, 0x1, 0x0, 0x1, [@ETHTOOL_A_HEADER_DEV_NAME={0x14, 0x2, 'syz_tun\x00'}]}]}, 0x34}}, 0x0)

executing program 2:
madvise(&(0x7f0000ffd000/0x3000)=nil, 0x3011, 0x17)
madvise(&(0x7f0000ffe000/0x2000)=nil, 0x2000, 0x15)
madvise(&(0x7f0000ffd000/0x3000)=nil, 0x3000, 0x8)

executing program 3:
bpf$PROG_LOAD(0x5, &(0x7f00002a0fb8)={0x9, 0x4, &(0x7f0000000000)=ANY=[@ANYBLOB="85000000ceb6ece19d1f06d49ef5142061000000004500000000000000250000"], &(0x7f0000000040)='syzkaller\x00', 0x4, 0x99, &(0x7f0000000180)=""/153, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x8, 0x0, 0x0, 0x10, 0x0, 0xfffffffffffffed8}, 0x3f)
r0 = open_tree(0xffffffffffffff9c, &(0x7f0000000640)='\x00', 0x89901)
fchdir(r0)
syz_genetlink_get_family_id$nl80211(&(0x7f0000000200), 0xffffffffffffffff)
r1 = openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000080)='cpu.stat\x00', 0x275a, 0x0)
write$UHID_CREATE2(r1, &(0x7f0000000180)=ANY=[], 0x118)
mmap(&(0x7f0000000000/0x3000)=nil, 0x3000, 0x5, 0x12, r1, 0x0)
openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000040)='cpu.stat\x00', 0x275a, 0x0)

executing program 2:
r0 = openat$smackfs_load(0xffffffffffffff9c, &(0x7f0000000180)='/sys/fs/smackfs/load-self2\x00', 0x2, 0x0)
write$smackfs_load(r0, &(0x7f00000001c0)={'^++}*]#-', 0x20, ':', 0x20, 'wxl'}, 0xf)
preadv(r0, &(0x7f0000003d00)=[{&(0x7f0000002ac0)=""/201, 0xc9}], 0x1, 0xf, 0x0)

executing program 1:
bind$alg(0xffffffffffffffff, &(0x7f0000000000)={0x26, 'rng\x00', 0x0, 0x0, 'drbg_nopr_hmac_sha384\x00'}, 0x58)
ioctl$sock_SIOCGIFVLAN_SET_VLAN_NAME_TYPE_CMD(0xffffffffffffffff, 0x8982, &(0x7f0000000000))
setsockopt$IP_VS_SO_SET_ADD(0xffffffffffffffff, 0x0, 0x482, &(0x7f0000000040)={0x0, @dev, 0x0, 0x2, 'sed\x00'}, 0x2c)
mount(0x0, &(0x7f0000000240)='.\x00', &(0x7f000015bffc)='nfs\x00', 0x0, &(0x7f0000000000))

executing program 1:
r0 = bpf$MAP_CREATE(0x0, &(0x7f00000009c0)=@base={0x19, 0x4, 0x8, 0x8}, 0x48)
r1 = bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x11, 0xc, &(0x7f0000000440)=ANY=[@ANYBLOB="1800000000000000000000000000000018110000", @ANYRES32=r0, @ANYBLOB="0000000000000000b7080000000000107b8af8ff00000000bfa200000000000007020000f8ffffffb703000008000000b7"], &(0x7f0000000240)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f00000001c0)={&(0x7f0000000080)='kfree\x00', r1}, 0x10)
r2 = socket$nl_route(0x10, 0x3, 0x0)
r3 = socket$inet6_udp(0xa, 0x2, 0x0)
ioctl$sock_SIOCGIFINDEX(r3, 0x8933, &(0x7f0000000c80)={'lo\x00', <r4=>0x0})
sendmsg$nl_route_sched(r2, &(0x7f0000001200)={0x0, 0x0, &(0x7f0000000000)={&(0x7f0000000040)=@newqdisc={0x38, 0x24, 0x4ee4e6a52ff56541, 0x0, 0x0, {0x0, 0x0, 0x0, r4, {}, {0xffff, 0xffff}}, [@qdisc_kind_options=@q_fq={{0x7}, {0xc, 0x2, [@TCA_FQ_PLIMIT={0x8}]}}]}, 0x38}}, 0x0)

executing program 2:
mknod(&(0x7f0000000040)='./file0\x00', 0x8001420, 0x0)
bpf$BPF_BTF_LOAD(0x12, &(0x7f0000000140)={&(0x7f0000000040)={{0xeb9f, 0x1, 0x0, 0x18, 0x0, 0xc, 0xc, 0x2, [@func_proto]}}, 0x0, 0x26}, 0x20)
r0 = socket(0x1d, 0x2, 0x6)
ioctl$ifreq_SIOCGIFINDEX_vcan(r0, 0x8933, &(0x7f0000000000)={'vxcan0\x00', <r1=>0x0})
syz_usb_connect(0x0, 0x2d, &(0x7f0000000000)=ANY=[@ANYBLOB="120100007516b7108c0d0e008f8e0018030109021b0001000000000904080001030000000905", @ANYBLOB="8fcf"], 0x0)
r2 = syz_open_dev$evdev(&(0x7f0000000600), 0x6828, 0x0)
syz_usb_connect$hid(0x0, 0x36, &(0x7f00000000c0)={{0x12, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5ac, 0x265, 0x0, 0x0, 0x0, 0x0, 0x1, [{{0x9, 0x2, 0x24, 0x1, 0x0, 0x0, 0x0, 0x0, [{{0x9, 0x4, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, {0x9}}}]}}]}}, 0x0)
ioctl$EVIOCGKEYCODE_V2(r2, 0x40284504, &(0x7f00000000c0)=""/159)
bind$can_j1939(r0, &(0x7f0000000040)={0x1d, r1, 0x1}, 0x18)
syz_io_uring_setup(0x2ddd, &(0x7f0000001780)={0x0, 0x0, 0x10100}, &(0x7f0000000240), &(0x7f0000001280)=<r3=>0x0)
r4 = socket$inet6(0xa, 0x3, 0x1)
r5 = socket$nl_xfrm(0x10, 0x3, 0x6)
setsockopt$netlink_NETLINK_ADD_MEMBERSHIP(r5, 0x10e, 0x1, &(0x7f0000000400), 0x2c)
sendmmsg(r4, &(0x7f0000000480), 0x2e9, 0x0)
syz_io_uring_submit(0x0, r3, &(0x7f00000001c0)=@IORING_OP_POLL_ADD={0x6, 0x0, 0x0, @fd_index=0x4})
write(0xffffffffffffffff, &(0x7f0000000180)="2000000012005f0214f9f4070000fbe40a0000000000", 0x41d)
r6 = socket$nl_route(0x10, 0x3, 0x0)
r7 = socket$inet6_udp(0xa, 0x2, 0x0)
ioctl$sock_SIOCGIFINDEX(r7, 0x8933, &(0x7f0000000040)={'lo\x00', <r8=>0x0})
sendmsg$nl_route_sched(r6, &(0x7f00000012c0)={0x0, 0x0, &(0x7f0000000580)={&(0x7f0000000080)=@newqdisc={0x24, 0x25, 0x4ee4e6a52ff56541, 0x0, 0x0, {0x0, 0x0, 0x0, r8, {}, {0x0, 0xffff}}}, 0x24}}, 0x0)

executing program 1:
r0 = socket$inet(0x2, 0x4000000000000001, 0x0)
setsockopt$inet_tcp_TCP_MD5SIG(r0, 0x6, 0xe, &(0x7f00000004c0)={@in={{0x2, 0x0, @loopback}}, 0x0, 0x0, 0x7, 0x0, "98d3340600c7aa11897ecaab876eab79576839c5656be8410f2802e944af80373be2666b665770173fbd1883303b6ac4749393ad08f139a68f00"}, 0xd8)
bind$inet(r0, &(0x7f0000000480)={0x2, 0x4e23, @multicast1}, 0x10)
sendto$inet(r0, 0x0, 0x0, 0x200007fd, &(0x7f0000000000)={0x2, 0x24e23, @loopback}, 0x10)
write$binfmt_elf64(r0, &(0x7f00000000c0)=ANY=[], 0xc63b9e35)
sendmsg$IPCTNL_MSG_TIMEOUT_DEFAULT_GET(r0, &(0x7f0000000440)={0x0, 0x0, &(0x7f0000000300)={&(0x7f0000000380)={0x14}, 0x14}}, 0x48885)
ioctl$FS_IOC_ADD_ENCRYPTION_KEY(0xffffffffffffffff, 0xc0406618, 0x0)

executing program 3:
r0 = syz_init_net_socket$bt_hci(0x1f, 0x3, 0x1)
bind$bt_hci(r0, &(0x7f0000000100)={0x1f, 0xffff, 0x1}, 0x6)

[  650.618109][T14650] usb 3-1: new high-speed USB device number 24 using dummy_hcd
[  650.898941][T14650] usb 3-1: Using ep0 maxpacket: 16
executing program 3:
syz_mount_image$bfs(&(0x7f0000000000), &(0x7f0000000080)='./file0\x00', 0x0, &(0x7f0000000280)=ANY=[@ANYBLOB="f8556c76fa196b4db4571d6bcdc9aad8a52154b8ba70e9b7dd42ce139df72938e03c184d8a3f74c28697eb8f75bdcc06fc2f1cf78448ef583ba09388f4219ec8e0f5dd900d9497b8e0e7d6810f1f3bd6fb69e05d3638bf0cd49444902709938cc3201c7b45245061083ff59ae0233af5f1ddc689b51593db7a5589b207f380e5430665f4e24f7aa9452e4bcbab6c8f1d5ab613fa8c081b63e3cde868e1e00b02cbc24d1d8f57047d3e5c9ee6ae82da4f59d78bc1f2891034250d26b4bdeaf5f0c31470e30631bf1d", @ANYRES64, @ANYRES8=0x0, @ANYRES32], 0xf, 0xb1, &(0x7f00000000c0)="$eJzs1yFywkAUBuCXdJqJretMRXVMr9BepVNZDINKDFfgIlwpCoOMB5ZJSAYRDgDD94m3+/6dVWv2pWz7saki0joiVe/LfbrK6ub/d7Gqm++Y+ZlHPKA8IuvXMiI+34Y+dtP7X86j7Yq/tnuZXy5uZAAAwN3K42vaHlPfn9IYHMYpIOK1L6NyqP79AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwPM4BwAA//9x7DAs")

executing program 4:
r0 = socket$inet6_udplite(0xa, 0x2, 0x88)
sendmmsg$inet6(r0, &(0x7f0000002100)=[{{&(0x7f0000000180)={0xa, 0x4e21, 0x0, @ipv4={'\x00', '\xff\xff', @remote}}, 0x1c, 0x0, 0x0, &(0x7f0000000880)=[@pktinfo={{0x20, 0x29, 0x32, {@ipv4={'\x00', '\xff\xff', @initdev={0xac, 0x1e, 0x0, 0x0}}}}}], 0x20}}], 0x1, 0x0)

executing program 4:
r0 = open(&(0x7f0000000080)='./bus\x00', 0x400141042, 0x0)
mmap(&(0x7f0000001000/0xa000)=nil, 0xa000, 0x7800007, 0x12, r0, 0x0)
r1 = creat(&(0x7f0000000000)='./bus\x00', 0x0)
ftruncate(r1, 0x81fd)
r2 = socket$can_bcm(0x1d, 0x2, 0x2)
connect$can_bcm(r2, &(0x7f0000000180), 0x10)
sendmsg$can_bcm(r2, &(0x7f00000001c0)={&(0x7f0000000000), 0x10, &(0x7f0000000140)={&(0x7f0000002180)=ANY=[], 0x48}}, 0x0)

[  651.035078][T14650] usb 3-1: config 0 has an invalid interface number: 8 but max is 0
[  651.050617][T14650] usb 3-1: config 0 has no interface number 0
[  651.066296][T14650] usb 3-1: config 0 interface 8 altsetting 0 endpoint 0x8F has an invalid bInterval 0, changing to 7
[  651.092590][T14650] usb 3-1: config 0 interface 8 altsetting 0 endpoint 0x8F has invalid wMaxPacketSize 0
executing program 4:
syz_mount_image$fuse(0x0, &(0x7f0000000140)='./file0\x00', 0x0, 0x0, 0x0, 0x0, 0x0)
pipe2$9p(&(0x7f0000000240)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff}, 0x0)
write$P9_RVERSION(r1, &(0x7f0000000040)=ANY=[@ANYBLOB="1500000065ffff001000000800395032303030"], 0x15)
r2 = dup(r1)
write$FUSE_BMAP(r2, &(0x7f0000000100)={0x18}, 0x18)
write$FUSE_DIRENT(r2, &(0x7f0000000000)=ANY=[@ANYBLOB="58000000000000009fed2788c5532994414b47034801d524faf416638217", @ANYRES32], 0x58)
mount$9p_fd(0x0, &(0x7f0000000180)='./file0\x00', &(0x7f0000000200), 0x0, &(0x7f0000000280)=ANY=[@ANYBLOB='trans=fd,rfdno=', @ANYRESHEX=r0, @ANYBLOB=',wfdno=', @ANYRESHEX=r1])
chdir(&(0x7f0000000100)='./file0\x00')
read$FUSE(r0, &(0x7f0000000300)={0x2020}, 0x2020)
openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000040)='memory.events\x00', 0x275a, 0x0)

executing program 3:
syz_mount_image$fuse(0x0, &(0x7f0000000140)='./file0\x00', 0x0, 0x0, 0x0, 0x0, 0x0)
pipe2$9p(&(0x7f0000000240)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff}, 0x0)
write$P9_RVERSION(r1, &(0x7f0000000040)=ANY=[@ANYBLOB="1500000065ffff001000000800395032303030"], 0x15)
r2 = dup(r1)
write$FUSE_BMAP(r2, &(0x7f0000000100)={0x18}, 0x18)
write$FUSE_DIRENT(r2, &(0x7f0000000000)=ANY=[@ANYBLOB="58000000000000009fed2788c5532994414b47034801d524faf416638217", @ANYRES32], 0x58)
mount$9p_fd(0x0, &(0x7f0000000180)='./file0\x00', &(0x7f0000000200), 0x0, &(0x7f0000000280)=ANY=[@ANYBLOB='trans=fd,rfdno=', @ANYRESHEX=r0, @ANYBLOB=',wfdno=', @ANYRESHEX=r1])
chdir(&(0x7f0000000100)='./file0\x00')
read$FUSE(r0, &(0x7f0000000300)={0x2020}, 0x2020)
openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000040)='memory.events\x00', 0x275a, 0x0)

[  651.229222][T16569] loop0: detected capacity change from 0 to 32768
[  651.234964][T14650] usb 3-1: New USB device found, idVendor=0d8c, idProduct=000e, bcdDevice=8e.8f
[  651.247343][T16569] BTRFS: device fsid ed167579-eb65-4e76-9a50-61ac97e9b59d devid 1 transid 8 /dev/loop0 (7:0) scanned by syz-executor.0 (16569)
[  651.265598][T14650] usb 3-1: New USB device strings: Mfr=0, Product=24, SerialNumber=3
[  651.287829][T14650] usb 3-1: Product: syz
[  651.300924][T14650] usb 3-1: SerialNumber: syz
[  651.307090][T16569] BTRFS info (device loop0): first mount of filesystem ed167579-eb65-4e76-9a50-61ac97e9b59d
[  651.322655][T14650] usb 3-1: config 0 descriptor??
executing program 4:
r0 = socket$alg(0x26, 0x5, 0x0)
bind$alg(r0, &(0x7f0000000000)={0x26, 'skcipher\x00', 0x0, 0x0, 'ecb(cipher_null)\x00'}, 0x58)
accept$alg(r0, 0x0, 0x0)
socket$netlink(0x10, 0x3, 0x0)
socket(0x2, 0x80802, 0x0)
bpf$BPF_PROG_RAW_TRACEPOINT_LOAD(0x5, &(0x7f0000000440)={0x11, 0x8, &(0x7f00000002c0)=@framed={{0x18, 0x8}, [@func={0x85, 0x0, 0x1, 0x0, 0x3}, @initr0, @exit, @alu={0x6, 0x1, 0xa, 0xa, 0xa}]}, &(0x7f0000000000)='GPL\x00', 0x4, 0xec, &(0x7f00000004c0)=""/236}, 0x80)
socket(0x10, 0x3, 0x0)
socket$packet(0x11, 0x3, 0x300)
pselect6(0x40, &(0x7f00000001c0), 0x0, &(0x7f00000002c0)={0x3ff}, &(0x7f0000000300)={0x0, 0x3938700}, 0x0)

[  651.337411][T16569] BTRFS info (device loop0): using sha256 (sha256-avx2) checksum algorithm
[  651.386995][T14650] cm109 3-1:0.8: invalid payload size 0, expected 4
[  651.410111][T14650] input: CM109 USB driver as /devices/platform/dummy_hcd.2/usb3/3-1/3-1:0.8/input/input25
executing program 1:
r0 = socket$nl_generic(0x10, 0x3, 0x10)
r1 = syz_genetlink_get_family_id$ethtool(&(0x7f0000000480), 0xffffffffffffffff)
sendmsg$ETHTOOL_MSG_PRIVFLAGS_SET(r0, &(0x7f0000000b80)={0x0, 0x0, &(0x7f00000000c0)={&(0x7f0000000240)=ANY=[@ANYBLOB=',\x00\x00\x00', @ANYRES16=r1, @ANYBLOB="010000000000000000002100000018000180140002"], 0x2c}}, 0x0)

[  651.575366][T16569] BTRFS info (device loop0): rebuilding free space tree
[  651.604499][T16590] UDC core: USB Raw Gadget: couldn't find an available UDC or it's busy
[  651.626040][T16590] misc raw-gadget: fail, usb_gadget_register_driver returned -16
executing program 4:
syz_mount_image$iso9660(&(0x7f0000000200), &(0x7f0000000000)='./file1\x00', 0x2008c16, &(0x7f0000000700)={[{@check_relaxed}, {@iocharset={'iocharset', 0x3d, 'cp860'}}, {@map_off}, {@map_normal}, {@nocompress}, {@check_strict}, {@check_strict}, {@cruft}, {@mode={'mode', 0x3d, 0x7}}, {@map_off}, {}, {@check_strict}, {@iocharset={'iocharset', 0x3d, 'maccenteuro'}}, {@unhide}, {@overriderock}]}, 0x3, 0x9f5, &(0x7f0000000900)="$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")
syz_mount_image$ext4(&(0x7f0000000440)='ext4\x00', &(0x7f0000000480)='./file0\x00', 0x0, &(0x7f0000000000)={[{@inode_readahead_blks={'inode_readahead_blks', 0x3d, 0x100000}}, {@bh}, {@mblk_io_submit}, {@test_dummy_encryption}, {@jqfmt_vfsv0}, {@usrjquota, 0x2e}], [], 0x2e}, 0x84, 0x46f, &(0x7f0000000580)="$eJzs289vFFUcAPDvbLvlt62IP/ihVtHY+KOlBZWDF40mXExM9IDHWgpBCjW0JkKIVGPwaPgL1KOJf4EnvRj1pPGqiRcTY0IMF9GDGTO7M7C0u+v+ahfczycZeG/mTd/7zszbfTNvJ4CBNZ79k0Rsj4ifRiJGq9mbC4xX/7t29cLcX1cvzCWRpq/+kVTK/Xn1wlxRtNhvW56ZKEWUPkhib516l86dPzW7sDB/Ns9PLZ9+a2rp3PmnTp6ePTF/Yv7MzOHDhw5OP/vMzNM9iXNH1tY97y7u233k9csvzx29/Ma3n2frt+fba+OoGuu6zvEYv/lY1ng04tc0Tbuu41axoyadDPexIbRlKCKy01XO+n+MxlDcOHmj8dL7fW0csK7SNE03rVk7VCRWUuB/LIl+twDoj+KLPrv/LZYNHH703ZXnqzdAWdzX8qW6ZThKeZnyqvvbXhqPiKMrf3+cLVH3OQQAQG99mY1/nqw3/ivFPTXl7ojq3NBYRNwZETsj4q6I2BURd0dUyt4bEfe1Wf/4qvza8c8PWzoKrEXZ+O+5fG7r5vFfMfqLsaE8t6MSfzk5fnJh/kB+TCaivCnLTzep46sXf/yo0bba8V+2ZPUXY8G8Hb8Pr3pAd2x2ebabmGtdeS9iz3C9+JPrMwFJROyOiD0d/P3smJ18/LN9jbb/d/xN9GCeKf004rHq+V+JVfEXkubzk1ObY2H+wFRxVaz13feXXmlUf1fx90B2/rfWvf6vxz+W1M7XLrVfx6WfP2x4T9Pp9T+SvFZJj+Tr3pldXj47HTGSrKxdP3Nj3yJflM/in9hfv//vjPjnk3y/vRGRXcT3R8QDEfFg3vaHIuLhiNjfJP5vXnjkzc7jX19Z/MfaOv/tJ4ZOff1Fo/pbO/+HKqmJfE0rn3+tNrCbYwcAAAC3i1LlN/BJafJ6ulSanKz+hn9XbC0tLC4tP3F88e0zx6q/lR+Lcql40jVa8zx0On82XORnVuUPVp4bp2mabqnkJ+cWF9ZrTh1ozbYG/T/z21C/Wwesu7bm0Rq90QbclryvCYNL/4fB1Wr/L69zO4CN5/sfBle9/n8x4lofmgJsMN//MLj0fxhc+j8MLv0fBlI37/U3S+w80vHuaVe1b84D63D3X9blaDRLDG1gXb1MRKnupnJE3CItbJIo3RrNqCY2RUSrhS92emG3nejzBxMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAECP/BsAAP//cGjokQ==")
bpf$OBJ_GET_MAP(0x7, &(0x7f00000008c0), 0x10)
mount$fuse(0x20000000, &(0x7f0000000400)='./file0\x00', 0x0, 0x223216, 0x0)

executing program 3:
lsetxattr$system_posix_acl(&(0x7f0000000400)='.\x00', &(0x7f0000000440)='system.posix_acl_default\x00', &(0x7f00000000c0)=ANY=[@ANYBLOB="02000000010000000000000002000000", @ANYRES32=0xee01, @ANYBLOB="02000000", @ANYRES32=0xee00, @ANYBLOB="02000000", @ANYRES32=0xee00, @ANYBLOB="02000000", @ANYRES32=0x0, @ANYBLOB="040000000000800008000000", @ANYRES32=0x0, @ANYBLOB='\b\x00\x00\x00', @ANYRES32=0x0, @ANYBLOB='\b\x00\x00\x00', @ANYRES32=0x0, @ANYBLOB="100000000000000020"], 0x5c, 0x0)
creat(&(0x7f0000000080)='./bus\x00', 0x0)
mkdirat(0xffffffffffffff9c, &(0x7f00000001c0)='./file0\x00', 0x0)
lsetxattr$system_posix_acl(&(0x7f0000002440)='./bus\x00', &(0x7f0000002480)='system.posix_acl_access\x00', &(0x7f00000024c0)={{}, {0x1, 0x3}, [{0x2, 0x1}, {0x2, 0x4, 0xee01}, {}, {0x2, 0x6}, {0x2, 0x5}, {}], {0x4, 0x6}, [{0x8, 0x2}, {0x8, 0x1}, {0x8, 0x2}], {0x10, 0x2}}, 0x6c, 0x0)
openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000080)='freezer.self_freezing\x00', 0x275a, 0x0)

[  651.673851][T16569] BTRFS info (device loop0): disabling free space tree
[  651.687371][T14980] usb 3-1: USB disconnect, device number 24
[  651.705084][    C0] cm109 3-1:0.8: cm109_urb_ctl_callback: urb status -71
[  651.712561][    C0] cm109 3-1:0.8: cm109_submit_buzz_toggle: usb_submit_urb (urb_ctl) failed -19
executing program 1:
r0 = socket$nl_generic(0x10, 0x3, 0x10)
r1 = syz_genetlink_get_family_id$gtp(&(0x7f0000000040), 0xffffffffffffffff)
sendmsg$GTP_CMD_NEWPDP(r0, &(0x7f0000000180)={0x0, 0x0, &(0x7f00000000c0)={&(0x7f00000002c0)=ANY=[@ANYBLOB=',\x00\x00\x00', @ANYRES16=r1, @ANYBLOB="010000000000000000000300000008000100", @ANYRES32=0x0, @ANYBLOB="080002"], 0x2c}}, 0x0)

[  651.725905][T16569] BTRFS info (device loop0): clearing compat-ro feature flag for FREE_SPACE_TREE (0x1)
[  651.752522][T14980] cm109 3-1:0.8: cm109_toggle_buzzer_sync: usb_control_msg() failed -19
executing program 1:
bpf$ENABLE_STATS(0x20, 0x0, 0x0)
bpf$MAP_CREATE_CONST_STR(0x0, &(0x7f0000000340), 0x48)
epoll_create(0xb)
bpf$ENABLE_STATS(0x20, 0x0, 0x0)
openat$ttyS3(0xffffffffffffff9c, &(0x7f00000003c0), 0x0, 0x0)
openat$binderfs(0xffffffffffffff9c, &(0x7f00000000c0)='./binderfs/binder0\x00', 0x0, 0x0)
r0 = syz_open_procfs(0xffffffffffffffff, &(0x7f0000000080)='fdinfo\x00')
syz_open_procfs(0xffffffffffffffff, &(0x7f0000006100)='cmdline\x00')
getdents(r0, &(0x7f0000000bc0)=""/4096, 0x1000)

[  651.772552][T16569] BTRFS info (device loop0): clearing compat-ro feature flag for FREE_SPACE_TREE_VALID (0x2)
[  651.868657][T16628] loop4: detected capacity change from 0 to 1764
executing program 4:
r0 = syz_init_net_socket$bt_hci(0x1f, 0x3, 0x1)
bind$bt_hci(r0, &(0x7f0000000100)={0x1f, 0xffff, 0x1}, 0x6)

[  651.942404][T16628] iso9660: Corrupted directory entry in block 2 of inode 1920
executing program 1:
r0 = epoll_create1(0x0)
r1 = syz_open_dev$dri(&(0x7f0000000080), 0x1, 0x0)
r2 = dup2(r1, r1)
read$FUSE(r2, 0x0, 0x0)
ioctl$DRM_IOCTL_WAIT_VBLANK(r2, 0xc018643a, &(0x7f00000001c0)={0x14000000})
epoll_ctl$EPOLL_CTL_ADD(r0, 0x1, r2, &(0x7f0000000140))

executing program 0:
r0 = socket$nl_generic(0x10, 0x3, 0x10)
r1 = syz_genetlink_get_family_id$nl80211(&(0x7f0000000080), 0xffffffffffffffff)
ioctl$sock_SIOCGIFINDEX_80211(r0, 0x8933, &(0x7f00000000c0)={'wlan1\x00', <r2=>0x0})
sendmsg$NL80211_CMD_SET_STATION(r0, &(0x7f00000002c0)={0x0, 0x0, &(0x7f0000000100)={&(0x7f0000000400)={0x34, r1, 0x1, 0x0, 0x0, {{}, {@val={0x8, 0x3, r2}, @void}}, [@NL80211_ATTR_STA_FLAGS2={0xc, 0x43, {0x8001}}, @NL80211_ATTR_MAC={0xa}]}, 0x34}}, 0x0)

executing program 4:
socketpair(0x15, 0x5, 0x0, &(0x7f0000001200))
r0 = socket$inet6(0xa, 0x1, 0x0)
setsockopt$inet6_IPV6_FLOWLABEL_MGR(r0, 0x29, 0x20, &(0x7f0000000200)={@private0, 0x800, 0x0, 0x1, 0x1}, 0x20)
setsockopt$inet6_int(r0, 0x29, 0x1000000000021, &(0x7f0000000180)=0x1, 0x23)
connect$inet6(r0, &(0x7f0000000000)={0xa, 0x0, 0x380000, @rand_addr=' \x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'}, 0x1c)
setsockopt$inet6_IPV6_FLOWLABEL_MGR(r0, 0x29, 0x20, &(0x7f0000000100)={@rand_addr=' \x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02', 0x0, 0x0, 0xff, 0x9}, 0x20)
setsockopt$inet6_IPV6_FLOWLABEL_MGR(r0, 0x29, 0x20, &(0x7f0000000080)={@loopback, 0x1, 0x0, 0x0, 0x1, 0x0, 0x401}, 0x20)
getsockopt$inet6_IPV6_FLOWLABEL_MGR(r0, 0x29, 0x20, &(0x7f0000000300)={@local}, &(0x7f00000004c0)=0x37)
setsockopt$MRT6_DEL_MFC_PROXY(r0, 0x29, 0xd3, &(0x7f0000000000)={{0xa, 0x4e22, 0x9, @remote, 0x3}, {0xa, 0x4e20, 0x8, @private1={0xfc, 0x1, '\x00', 0x1}, 0x80000000}, 0x1, {[0xfff, 0x5, 0x0, 0x200, 0x25, 0x200, 0x1, 0x4]}}, 0x5c)
r1 = socket$inet6(0xa, 0x1, 0x0)
setsockopt$inet6_IPV6_FLOWLABEL_MGR(r1, 0x29, 0x20, &(0x7f0000000200)={@private0, 0x800, 0x0, 0xff, 0x1}, 0x20)
setsockopt$inet6_int(r1, 0x29, 0x1000000000021, &(0x7f0000000180)=0x1, 0x23)

executing program 3:
mknod(&(0x7f0000000040)='./file0\x00', 0x8001420, 0x0)
bpf$BPF_BTF_LOAD(0x12, &(0x7f0000000140)={&(0x7f0000000040)={{0xeb9f, 0x1, 0x0, 0x18, 0x0, 0xc, 0xc, 0x2, [@func_proto]}}, 0x0, 0x26}, 0x20)
r0 = socket(0x1d, 0x2, 0x6)
ioctl$ifreq_SIOCGIFINDEX_vcan(r0, 0x8933, &(0x7f0000000000)={'vxcan0\x00', <r1=>0x0})
syz_usb_connect(0x0, 0x2d, &(0x7f0000000000)=ANY=[@ANYBLOB="120100007516b7108c0d0e008f8e0018030109021b0001000000000904080001030000000905", @ANYBLOB="8fcf"], 0x0)
r2 = syz_open_dev$evdev(&(0x7f0000000600), 0x6828, 0x0)
syz_usb_connect$hid(0x0, 0x36, &(0x7f00000000c0)={{0x12, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5ac, 0x265, 0x0, 0x0, 0x0, 0x0, 0x1, [{{0x9, 0x2, 0x24, 0x1, 0x0, 0x0, 0x0, 0x0, [{{0x9, 0x4, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, {0x9}}}]}}]}}, 0x0)
ioctl$EVIOCGKEYCODE_V2(r2, 0x40284504, &(0x7f00000000c0)=""/159)
bind$can_j1939(r0, &(0x7f0000000040)={0x1d, r1, 0x1}, 0x18)
syz_io_uring_setup(0x2ddd, &(0x7f0000001780)={0x0, 0x0, 0x10100}, &(0x7f0000000240), &(0x7f0000001280)=<r3=>0x0)
r4 = socket$inet6(0xa, 0x3, 0x1)
r5 = socket$nl_xfrm(0x10, 0x3, 0x6)
setsockopt$netlink_NETLINK_ADD_MEMBERSHIP(r5, 0x10e, 0x1, &(0x7f0000000400), 0x2c)
sendmmsg(r4, &(0x7f0000000480), 0x2e9, 0x0)
syz_io_uring_submit(0x0, r3, &(0x7f00000001c0)=@IORING_OP_POLL_ADD={0x6, 0x0, 0x0, @fd_index=0x4})
write(0xffffffffffffffff, &(0x7f0000000180)="2000000012005f0214f9f4070000fbe40a0000000000", 0x41d)
r6 = socket$nl_route(0x10, 0x3, 0x0)
r7 = socket$inet6_udp(0xa, 0x2, 0x0)
ioctl$sock_SIOCGIFINDEX(r7, 0x8933, &(0x7f0000000040)={'lo\x00', <r8=>0x0})
sendmsg$nl_route_sched(r6, &(0x7f00000012c0)={0x0, 0x0, &(0x7f0000000580)={&(0x7f0000000080)=@newqdisc={0x24, 0x25, 0x4ee4e6a52ff56541, 0x0, 0x0, {0x0, 0x0, 0x0, r8, {}, {0x0, 0xffff}}}, 0x24}}, 0x0)

executing program 2:
r0 = syz_open_procfs(0x0, &(0x7f0000000080)='net/tcp\x00')
lseek(r0, 0x7f, 0x0)
read$FUSE(r0, &(0x7f0000005fc0)={0x2020}, 0x2020)
r1 = socket$nl_route(0x10, 0x3, 0x0)
ioctl$ifreq_SIOCGIFINDEX_batadv_hard(r1, 0x8933, &(0x7f0000000040)={'batadv_slave_0\x00', <r2=>0x0})
r3 = socket$nl_route(0x10, 0x3, 0x0)
ioctl$sock_SIOCGIFINDEX(r3, 0x8933, &(0x7f0000000180)={'syz_tun\x00', <r4=>0x0})
sendmsg$nl_route(r1, &(0x7f0000000280)={0x0, 0x0, &(0x7f00000002c0)={&(0x7f0000000340)=@newlink={0x58, 0x10, 0x503, 0x0, 0x0, {}, [@IFLA_LINKINFO={0x38, 0x12, 0x0, 0x1, @hsr={{0x8}, {0x2c, 0x2, 0x0, 0x1, [@IFLA_HSR_MULTICAST_SPEC={0x5}, @IFLA_HSR_SLAVE2={0x8, 0x2, r2}, @IFLA_HSR_SLAVE1={0x8, 0x1, r4}, @IFLA_HSR_VERSION={0x5}, @IFLA_HSR_PROTOCOL={0x5, 0x7, 0x1}]}}}]}, 0x58}}, 0x0)
r5 = bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f0000000140)={&(0x7f0000000040)='btrfs_sync_fs\x00'}, 0x10)
ioctl$FICLONE(0xffffffffffffffff, 0x40049409, r5)
r6 = socket$netlink(0x10, 0x3, 0x0)
r7 = socket(0x10, 0x803, 0x0)
sendmsg$TIPC_NL_MON_GET(r7, &(0x7f0000000500)={&(0x7f00000004c0)={0x10, 0x0, 0x0, 0x80000}, 0xc, &(0x7f00000005c0)={0x0, 0x88}, 0x1, 0x0, 0x0, 0x1}, 0x0)
r8 = syz_genetlink_get_family_id$ipvs(&(0x7f0000000240), r7)
sendmsg$IPVS_CMD_ZERO(r6, &(0x7f0000000400)={&(0x7f00000001c0)={0x10, 0x0, 0x0, 0x2000}, 0xc, &(0x7f00000003c0)={&(0x7f0000000640)={0x88, r8, 0x20, 0x70bd27, 0x25dfdbff, {}, [@IPVS_CMD_ATTR_DEST={0x24, 0x2, 0x0, 0x1, [@IPVS_DEST_ATTR_L_THRESH={0x8, 0x6, 0x4}, @IPVS_DEST_ATTR_TUN_FLAGS={0x6, 0xf, 0x7f}, @IPVS_DEST_ATTR_TUN_PORT={0x6, 0xe, 0x4e23}, @IPVS_DEST_ATTR_U_THRESH={0x8, 0x5, 0x7}]}, @IPVS_CMD_ATTR_TIMEOUT_TCP_FIN={0x8, 0x5, 0x80000000}, @IPVS_CMD_ATTR_TIMEOUT_UDP={0x8, 0x6, 0xffff8000}, @IPVS_CMD_ATTR_DEST={0x40, 0x2, 0x0, 0x1, [@IPVS_DEST_ATTR_TUN_TYPE={0x5, 0xd, 0x1}, @IPVS_DEST_ATTR_ADDR={0x14, 0x1, @ipv6=@private0={0xfc, 0x0, '\x00', 0x1}}, @IPVS_DEST_ATTR_ADDR_FAMILY={0x6, 0xb, 0xa}, @IPVS_DEST_ATTR_U_THRESH={0x8, 0x5, 0x6d}, @IPVS_DEST_ATTR_PORT={0x6, 0x2, 0x4e22}, @IPVS_DEST_ATTR_PERSIST_CONNS={0x8, 0x9, 0x7ff}]}]}, 0x88}, 0x1, 0x0, 0x0, 0x4000001}, 0x8800)
r9 = bpf$MAP_CREATE(0x0, &(0x7f0000000440)=@base={0x19, 0x4, 0x4, 0x1}, 0x48)
bpf$MAP_UPDATE_ELEM(0x2, &(0x7f00000000c0)={r9, &(0x7f0000000000), &(0x7f0000000380)=@udp=r7, 0x2}, 0x20)
signalfd4(r6, &(0x7f00000002c0)={[0x1ff]}, 0x8, 0x800)
syz_genetlink_get_family_id$nl80211(&(0x7f0000000600), r7)
sendmsg$IPSET_CMD_TEST(r7, &(0x7f0000000700)={&(0x7f0000000000)={0x10, 0x0, 0x0, 0x8000000}, 0xc, &(0x7f0000000140)={&(0x7f0000000800)=ANY=[@ANYBLOB="980000000b060101000000000000000002000009100008800c000780060005404e24000064ffffffff00028008000900ffffffff06001df9ce40000400000800064000000004060005404e200000eaff1c40000000070900130073797a32000000001400170070696d3672656730000000000000bf20cc76460877ac947b14001700626f6e645f736c6176655f3100000000100007360c00194000000000000000090601dfd7365053a686dd467fd7fc2cc7b22bb7614176b6d64d39463ad9ce6a64a3566e264d3ee9da2d4bef7308190737128b3418805d64cb1977dc6bb7db796741362ab9b753d578057b258a79b7c1b2a3ee0b6c86d78c253f470eca2bad508735696f190601e3b27bc1183e4c93fff9766dabfb00b33a4758d1afcfa01988a9d663dca17cf8b8c99df6fb0463e473d7dad4f05811cda47e"], 0x98}, 0x1, 0x0, 0x0, 0x80}, 0x2)
getsockname$packet(r7, &(0x7f0000000100)={0x11, 0x0, <r10=>0x0, 0x1, 0x0, 0x6, @broadcast}, &(0x7f0000000200)=0x14)
sendmsg$nl_route(r6, &(0x7f00000000c0)={0x0, 0x0, &(0x7f0000000300)={&(0x7f0000001bc0)=@newlink={0x84, 0x10, 0xffffff1f, 0xee020000, 0x0, {0x0, 0x0, 0x0, 0x0, 0x0, 0x35288}, [@IFLA_LINKINFO={0x5c, 0x12, 0x0, 0x1, @ipip6={{0xb}, {0x4c, 0x2, 0x0, 0x1, [@IFLA_IPTUN_ENCAP_TYPE={0x6}, @IFLA_IPTUN_REMOTE={0x14, 0x3, @rand_addr=' \x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'}, @IFLA_IPTUN_COLLECT_METADATA={0x4}, @IFLA_IPTUN_LINK={0x8, 0x1, r10}, @IFLA_IPTUN_COLLECT_METADATA={0x4}, @IFLA_IPTUN_LOCAL={0x14, 0x2, @remote}, @IFLA_IPTUN_PROTO={0x5, 0x9, 0x29}]}}}, @IFLA_MASTER={0x8, 0xa, r10}]}, 0x84}}, 0x4000080)

[  652.284986][T16170] BTRFS info (device loop0): last unmount of filesystem ed167579-eb65-4e76-9a50-61ac97e9b59d
executing program 1:
r0 = syz_init_net_socket$bt_l2cap(0x1f, 0x5, 0x0)
bind$bt_l2cap(r0, &(0x7f00000001c0)={0x1f, 0x3, @fixed, 0x0, 0x1}, 0xe)

executing program 4:
r0 = openat$sw_sync(0xffffffffffffff9c, &(0x7f0000001700), 0x0, 0x0)
ioctl$SW_SYNC_IOC_CREATE_FENCE(r0, 0xc0285700, &(0x7f0000000080)={0x0, "d2c4924d5e89213dc64c3b6e6ff82a75e5318fca4288c2ffbdbec772020acd2c", <r1=>0xffffffffffffffff})
r2 = openat$sw_sync(0xffffffffffffff9c, &(0x7f0000000000), 0x0, 0x0)
ioctl$SW_SYNC_IOC_CREATE_FENCE(r2, 0xc0285700, &(0x7f00000002c0)={0x3, "421ae3753785259249154c944122ad063ff47d3bd7a8a45d6bb4c78a3ab4c981", <r3=>0xffffffffffffffff})
ioctl$SYNC_IOC_MERGE(r1, 0xc0303e03, &(0x7f00000000c0)={"e50d1af889b4ea0700000000000000f3c49e4906eddfecd83634e4a37ef94add", r3, <r4=>0xffffffffffffffff})
r5 = epoll_create1(0x0)
epoll_ctl$EPOLL_CTL_ADD(r5, 0x1, r4, &(0x7f0000000040))
ppoll(&(0x7f0000000200)=[{r3}], 0x1, 0x0, 0x0, 0x0)
ioctl$SW_SYNC_IOC_INC(r2, 0x40045701, &(0x7f0000000100)=0x1f)

executing program 1:
syz_mount_image$fuse(0x0, &(0x7f0000000140)='./file0\x00', 0x0, 0x0, 0x0, 0x0, 0x0)
pipe2$9p(&(0x7f0000000240)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff}, 0x0)
write$P9_RVERSION(r1, &(0x7f0000000040)=ANY=[@ANYBLOB="1500000065ffff001000000800395032303030"], 0x15)
r2 = dup(r1)
write$FUSE_BMAP(r2, &(0x7f0000000100)={0x18}, 0x18)
write$FUSE_DIRENT(r2, &(0x7f0000000000)=ANY=[@ANYBLOB="58000000000000009fed2788c5532994414b47034801d524faf416638217", @ANYRES32], 0x58)
mount$9p_fd(0x0, &(0x7f0000000180)='./file0\x00', &(0x7f0000000200), 0x0, &(0x7f0000000280)=ANY=[@ANYBLOB='trans=fd,rfdno=', @ANYRESHEX=r0, @ANYBLOB=',wfdno=', @ANYRESHEX=r1])
chdir(&(0x7f0000000100)='./file0\x00')
read$FUSE(r0, &(0x7f0000000300)={0x2020}, 0x2020)
openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000040)='memory.events\x00', 0x275a, 0x0)

executing program 1:
r0 = bpf$MAP_CREATE(0x0, &(0x7f0000000000)=@base={0x6, 0x4, 0x5b, 0x8a}, 0x48)
r1 = bpf$MAP_CREATE(0x0, &(0x7f0000000000)=@base={0x6, 0x4, 0x5b, 0x8a}, 0x48)
r2 = bpf$PROG_LOAD(0x5, &(0x7f0000000080)={0x1, 0x5, &(0x7f0000000500)=ANY=[@ANYBLOB="bf16000000000000b707000001009fa35070000000000000280000000000c00095000000000000002ba728041598d6fbd30cb599e83d24a3aa81d36bb3010100bd2321afb56fa54f26fb0b71d0e6adff07f1d8f7faf75e0f226bd99eea7960707142fa2dc79b9723741c4a0e168c1886d0d4d94f2f4e345c652fbc16ee988ee99fbfbf9b0a4def23d410f6296b32a834388107200759cda9036b4e369a9e152ddcc7b1b85f3c4744aeaccd3641110bec4e9027a0c8055bbfc3a96d2e8910c2c3b35967dec6e802f5ab3eea57b09a2ed4048d3b867ddd58211d6ececb0cd2b6d357b85a0218ce740068725837079e468ee207d2f73902fbcfcf49822775985bf31b715f5888b24efa000000000000ffffffdf0000000000000000000000000000020000000000000000000000000000b27cf3d1848a54d7132be1ffb0adf9deab29ea3323aa9fdfb52faf449c3bfd09000000b9349e31aa3701c38c527d3237c18e521ab219efdebb7b3de8f67581cf796a1d4223b90b80fcad3f6c962b9f292324b7ab7f7da31cf41ab12012fb1e0a494034127de745409e35a30b23bcee46762c2093bcc9eae5ee3e980026c96f80ee1a74e04bde740750fa4d9aaa705989b8e673e3296e52d307db98ca112874ec309baed0499104dcfe7c0f694bd5fc9e66d058b75fa4c81e5c9f42d9383e41d277b10392a96286744f049c3f128f8f92ef992239eafce5c1b3f97a297c9e49a0c3300ef7b7fb5f09e0c8a868a353409e34d3e82279637598f37ad380a447483cac394c7bbdcd0e3b1c39b2e00916de48a4e70f03cc415ba77af02c1d4cef5379da860aed8477dfa8ceefb405005c6977c78cdbf37704ec73755539280b064bda144910fe050038ec9e47de89298b7bf4d769ccc18eede00e8ca5457870eb30d211e23ccc8e06cd58b638c234bbb55ff413c86ba9affb12ec757c7234c270246c87a901160e6c07bf6cf8809c3a0d46ff7f000000000000ad1e1f493354b2822b9837421134c0167d78e6c24ed0a2768e825972ea3b774a1467c89fa0f82e8440105051e5510a33dcda5e143fbfff161c12ca389cbe4cc302b52e2101de18a1f1f7c551b3fa00055cc1c46c5fd9c26a54d43fa050645bd6109b113be7664e08bdd7115c61afcb718cf3c4680b2f6c7a84a4e378a9b15bc20f49e298727340e97c870800000047546103f123f661c84726e7c7c55eff231a1b033d8f841ba3442b2c7c503f3d0e7ab0e958adb862822e40009995ae166deb9856291a43a6f7eb2e32cefbf46306f2ef7be184f5e93ba5c8c2a4c04450b652b8d4c2ff030000000000000007c6bbd6cb2b240ce7d47ae636a5dbe9864a117d27326850a7c3b57086a4482c218b10af13d7be94987005088a83880ccab9c99220002af8c5e13d52c87c3a3ee6c08384865b66d2b4dcb5dd9cba16b64ebbbf8702ae12c77e6e34991a225c120a3c950942fe0bc9f2a1a7506d35e5b439edeb7088aeda890cf8a4a6f31ba6d9b8cb098f935bdcbb29fd0f1a342c9eed00000000ab6648a9dea0b6c91996d65da6c24a700a86c814459f3cdaaf99000000000000000000bf2130d1b32c826563c718d0ad23bc83ba3f3757210a057e177615c0683f000000000000006d4e0413ab52f5aaab812201d1aba3d70471fcd9b466569f3ef72f39d87fcccab514fcff030000629c9b73ce7bc4be7f8be71cb7b2d0a4acff8f6abe7dbad64dfa63966945d93c33b038ce0d890f85f8a6ab8487c383e24d4a8051f80e1811e387723a25dda119f64b35e71c5400000000000000000000000000000034c751ebdf3f207ea3df3d6c0002a41783078e56c70afe8016b3dd9dc7785b36e609f173cc747837d600283b3452c57a5d44cacd363589845637071320921d32c1663964eddec97cc33158bc306d8c3bdae8108a23d2dc96a5cdb518f58832ec0906aaec43659c79c8ad37b0f961f3beaa3e02f7762c5dd633d13b5e487e996597b2ab42c81eb7dd8390e13b395aacce4683e55bcfe8c17615257364365fd48bd77da79e52ce9adfe6dcb0c42c4d719347f3d16304fa000008ffffffffffffff003049ca923d059c0ab5d886a491adacb7e4b43b1b57586e5fe2aa611f6232a9b71882ce24fce75cf105fa57f000756755b7230e2c0c1fed5487271c4f2981cf8f4351ef5d08641dacaed000080000000000000000000000fa36bbac00bb77c933d3961556f3fe647b05643b0000000000000000000000967aef9c5706e13d5889e77dab80a2548ec31629b7355a2bb8b93e4b6323061f545b26accc4621b568ab0bfaf30aa4f60705532c4a09c0a4a5487c762167edf362be35b9c90ad7e372a66bbb1471aa21000000000000104061c66a7432f25687618e31dcef8c5d4a2457a93f3fc6d3d7131746c75ccf400fc1a7a51826832ef7f5fbc78827d937768443a1c1ca3aba93a34efd21aa1201d9225256df8de405d1f12c17cdaff3ad675aa333aa7e919459babd3cc1000000000000000000000000000000000000000000000000000000000000000059fdc6a54a2a8b28fa7d9b92aeb58e78e3b8594a5ef6bb67e52bf43b6145f544273a8f62852706c0abef368bfc72f92fa99a7bf121019cff8001fd7d2f6c2c295a5cab383235fec4c1decbed258ee9df8963c0fc828ad2119ffefe36c78692fffb6942b9da0922b2aa8f6b66c14ee7f42d5951edcc986356b41c0de3549f851ca340d9e425e355c1decb785a1042a72c1c98a084b04b1d9be473e50a15d76b110eda3b7cc1f2501211773cf510a43888422c1328476dd6f42659c61a18618fd28d5cd342c276aa9c4cc035077fa09d672b8dcfb3ac1751628647047d07338a8619037e3449a173ddd697f541a0795a2de7ef1396d70675341ebf004be122de04b5275fe7e53d28ebdc5051cec00759d73ca97229d93b965926060b6f91d01324bd458b425ea51c5d5b69551d599188fc6040370ac9ca7ae9eea9e5ede79bd66bd3d616dd7d7dd4c3a8fd055a3585af6fe7f5046c61154598cd33c33a48ece1072afd04b1fd85eb1655d9f3f813392c9634200d892dc6810b436820a1e0f6b464855e28953eb63cd3d6fc1b7bfb588ce28a51af1658d45d759a8399da55a3ff6597bb9f47167fe55ca240623a001e5fe15d9ddefea06a3750501916163844106c4ce662f418d9fc509e5447f712048d53e7e36ee7de083c5ea1119969d858eb6785395fc5a2c551de9a086cb4583f55c47828645e3046"], &(0x7f0000000140)='GPL\x00'}, 0x48)
r3 = bpf$MAP_CREATE(0x0, &(0x7f0000000000)=@base={0x6, 0x4, 0x5b, 0x8a}, 0x48)
bpf$PROG_BIND_MAP(0x23, &(0x7f0000000180)={r2, r3}, 0xc)
bpf$PROG_BIND_MAP(0x23, &(0x7f0000000100)={r2, r1}, 0xc)
bpf$PROG_BIND_MAP(0x23, &(0x7f00000001c0)={r2, r0}, 0xc)

executing program 2:
r0 = socket$rxrpc(0x21, 0x2, 0x2)
bind$rxrpc(r0, &(0x7f0000000340)=@in4={0x21, 0x3, 0x2, 0x10, {0x2, 0x0, @local}}, 0x24)
bind$rxrpc(r0, &(0x7f0000001280)=@in4={0x21, 0x4, 0x2, 0x10, {0x2, 0x0, @local}}, 0x24)
listen(r0, 0x0)

[  652.865011][T14650] usb 4-1: new high-speed USB device number 23 using dummy_hcd
executing program 0:
bpf$ENABLE_STATS(0x20, 0x0, 0x0)
r0 = bpf$PROG_LOAD(0x5, &(0x7f0000000200)={0x4, 0xe, &(0x7f00000011c0)=ANY=[@ANYBLOB="b702000000000000bfa30000000000000703000000fef7ff7a0af0fff80000ff79a4f0ff00000000b7060000efffffff2d6405000000000065040400010000000404000001007d60b7030000000000006a0a00fe00ba23008500000098000000b70000000000000095000000000000006f88300eaa171100756695acf0af839ec5300a584fe44c80de0b061417e9ade22cecede58ee094518a5800000082c81ddfe3960a29ea15fa7e22f0f3e51416b698f6da6fe8af496d22585ffab3af24974fae00d824313ffef788c6983945dd3663f79f67e78a48b24a4bcdc33b38c5f86e96111199f0f0af9f42099a0f54041889b971cf394bd43473a5ac2acab9768cbc52ff7f000000000000711727c4a32a6b7ecdae05d2b3fed4572eb0d88976d2adda68000010000000c47b18cf93996a43f5e080f57fadf535d8b3078ebe16b10160fad64474a7b558f7a56f41022feec18e013abd8fda2b96779e534d0675fbcc13ba9f9eb96319fd5b49521d5cb2ced401d7b6fce658f203a9c2da91116d986730da1be85b0000829512099df32814820fbf7be91cd13b77f4e4e599f8bbca388247856073472312a9ff4273b9cd08000000000000616e888cda842c661577818c2069cb41aa3b4b7fc28882cad315db3fffc5183deca7a32838e80ad70d4f55382c1879b71ec504d2f3e3883428ee350123a5cad346f6d517f6fcea5b6bc4fcffffffffffff03f419a6e45fd98e77da4a8202ebbdafe6b2e38c9d7e506f5da2958cf7f0d9b31ca3275e64e29d39d158cebe43308cf8760588001172e19685e9a334aec76530861b772a1da96f0a227514bd0bc26df2b50a45e4eceae1ddfe88d58879d12afdb295ce2edecb253e0471714fa124211203000000000000001f502b6c760655ffb20ae13a1a94f7ae229fbf5da7cae4f994ee82fc98c864c3e352ad16f98208cf1469dd6c1212582a3687f7dbdf708929643f3f0f4e947c40742452685ec044fc71eaca9ac692145677e14054331801b1412b39049ed782742f9a1b6aca9123b243c1a68c047f2db79701b62c8cc0d2f608c7f62d107ebc68df9f8d296721c9d465dad604bc0dc50000000000000002000000000000000000000568a4997dd54fa83aacd2d209f66de2e26dc2fd862a0b8ee149c148197176745fc8ff1dd5bd6611daa882298a37b041b34668d4662ea8fbe2e787dfc4c8bef2124f0439b2d18ec83361da5cc7324000b0a528db31b90bc1405b6d5301c34319ccae29b1d6034b665c79baeeeac5e71d24e2e3b6ffc5bc2dcb600e645c0048b45e286a49e888d21abfc817085d9c00e08525207e33505226fdda16e6da6dd31f7a1736029b87e8d6a05bcb356298d7dccd7de2af0885bd4939ff96ab74da3871b077e4058c8752ba4994eafed8b239d781638fa339fa0f7dd135c74d0f95d36cf02670cf27d205a45d4702f97b8b7c57b180c50b2b370dfb35dc895e8f05d6e71829f36150b2cde31469c4aea0c64850eb3f3e0dc35f8cdd76bdde2018366c3201307c370433762676f72e68c962430a0000000000000000000000000000e737dc2e1a3fdebbb510c663d24f72b954965201f775b3739c14dd4832647c028be09f2809fd396fa26532a30a37737e95f0f41dd024b7bf8a6bf807c9fd9b8c7a39717729339dc3054117cb95693bdd61edcc2860b66545e194a961bdc5457d76ae1a87050e12ead896f333735a000000000000000000400000602bfd2f1ace65f2e74dc9c1709cb73a37f40362b7904e8a0ea8d2d9805c924f9985d22972031a1223afa1288af3f48c93fcdb11963d0b748287448f722dc180e87637b662b11effabf45beda2e3a7e1adf8f94b619fa152b33440f2358a745848caf7000eb305c936d26964a2a85e133d01368b8d228d02f96064de261cf02c9632a0eb4ab259e8f4dd63d8b6d2d6b2a0c297bab7d04d73a381c29eaf344655b64e12f216fbc646cc6bd60ca773d187f2fd317f6cb2309d1a13526a44b7d9b2bf93947dc3ac3340a7a114051d33d152310574f0d784910dc1a8403f9200a8f5bbf3610c544437626236458f285196161496389b02ba46a72da0149b4ddfdd55f7862a07395752a37cb0244e94da310e0c0a148a9a48b149bf2f345f3f89813c9eb05160f63f0b363deee5cb77ea6e951857e1942e5c56d72d724af7aa24a8aadb512f3302972c53b0eb7a693e0b0c775b21aed72995cfe9e9347a07d43ce3db9f22d461e86416ffff6f2e4e36306630052a2b03ee36ec52af0d684fabd5f38adffaa6c5a7a8100d1aefaf8576b363690b76e2eb96b07ab790cf63cfc334b7469b5b5b397c622f7c3ee064f9272443bcb928b6f7a2450cd33550a42843b0b5ac9e37134c81bd56b72e1030b05a5b3ac47b5af22a9dff0700004adacc71db2b15b4ffd98e30224763382ade45d164be76877d63de448f3ee2cd29707484df87ea6e8e6333b5fcb1b8b43a7c005ea800000000000000000000010000000000387592adc78ccfe479549e6f4efc14c4a5cfe845e6157d6fe70b278147edf0e25065ec6b17f8022493d105c9c31121e7957aeec5f7f2af0446d128778c8bf15b87a0eec6f4c75966b5f0e06744bda63134223416102aea1254d57c390e1f84ec7d5c3a758ce59c9e2c4ce1f28b6783661e272bf1cb5c8ac177aa9c6ccbead9a96b22394afb840247e5d69473b836f070dc0bf9302e33b03d4e07395c82e33667726b51ff24b0bbea730702835159e3517ffb3da0d01833589fec3bdab629b21e5d9e87c3c58d962ff5e75c81f583c64b7d5a643674801e18b06ca98b49d9e28d004c7ebccf076c64ef71421f672b0948b18ab5af448ca9446e71ba6dd4bd15a12553066de7cb767a121d56d9d26ce27fdbe6721191f2ed1cc3f9c5e300000000c4793165b3cbf51c7d0cf9edf823641e1bc7db7803b60dc8b21e49a33a73ac00337067dfd3ecaf4e6dceee1048f300000000000000000000000000000000f8ff00000000007958a50896df65337581398793d0a9abe75251908c07d2957ca70ad7ac31aae536294d6a944cd35f46cb554d8aecae5a72cb24596d896ff9ad83473567b6cb9d032c395a1459399cea31ebafc1e77649b55af527ca0f1ac972ee72a78391473c1b9e0000000000000000004076eac7e605f8de6f0ce5702af52c5d78bac0097d92f078a3a98229ebf281c3c876d2614109b69967871fea621fb2a29a77a1516b51d9b1c3c5ef1436f50fad4a1cd925211fec61d37c8b410a20fbdeb642228d6cfeb8cda8eea3a7f343fcaa0459b9d916abb668d4799534307084ee7d854dd0850000000000000000000000002f40c3e24f9c0a56edf543425058ff00ebda26a43bdab770212186b84421d8b841cf9181d47c08cb392e414c1efba9978a97769e65ae443644dbdb32a50cdc717a34d1aa9ced37820a6d1cd0920a9a07e36a85e967bfa7f2caf1c9b52c06f4d178fbb91a169e9533e401819e57cab8147618196e7029327eeed624bb92a7462538dbd8a4b82f87df7982b44b160a598c75bafa5a9b388a4430bdbebc83ac2ad2da3ae80c851bc2fdb8d444597fdac4538aa33bbd204ffe534b15a1878be30157d0815d38fc2effeb7b87d6bd15e21c7b7c7d1ad7b3fd69b4bd06716a203e82f4c0413719eae0967fc70f03570375c2d0986b020066368e6a18f50d32f6fa95542f70b0cf850a3f25a9e76601587e9158b8cf107cc68e0263b270359dd3f4848a049a11659714f6a40df0fc79b3129bd9b1f27b433ae6dbf2c61be55f6a9a06cd6676e2193cf61876330d948b9986df5536574edd427376d308b328f961d821edec74b8eea8f3eb5e9b412f31b85c71ddea2838600ae982987233316bba8bfe260e556eefa9c6946acc5852d2f504d9d43e7d52621b892267642dedf4d6cc2ceaa0be2c070b87ded2785832344532fc562c6a8d39dd9e7233415bfbc74cde3b4afb43fe01e2f9161a1f7ec212c3c2938545efc041e65c8da6fa08004fc47a32b89dc1bf5aebe7b3668d72700b163a005ca227e017a1f90439fca246e7860d0b2536a859d1b077730000"], &(0x7f0000000340)='syzkaller\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x8, &(0x7f0000000000), 0x304, 0x10, &(0x7f0000000000), 0xfffffea2}, 0x48)
bpf$BPF_PROG_TEST_RUN(0xa, &(0x7f0000000640)={r0, 0x0, 0xe, 0x0, &(0x7f0000000040)="63eced8e46dc3f0adf33c9f7b986", 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x50)

executing program 2:
prlimit64(0x0, 0xe, &(0x7f0000000140)={0x8, 0x8b}, 0x0)
sched_setscheduler(0x0, 0x1, &(0x7f0000000080)=0x7)
r0 = getpid()
sched_setaffinity(0x0, 0x8, &(0x7f00000002c0)=0x2)
sched_setscheduler(r0, 0x2, &(0x7f0000000200)=0x4)
mmap(&(0x7f0000000000/0xb36000)=nil, 0xb36000, 0xb635773f06ebbeee, 0x8031, 0xffffffffffffffff, 0x0)
socketpair$unix(0x1, 0x3, 0x0, &(0x7f0000000380)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff})
connect$unix(r1, &(0x7f00000003c0)=@abs, 0x6e)
sendmmsg$unix(r2, &(0x7f0000000000), 0x651, 0x0)
recvmmsg(r1, &(0x7f00000000c0), 0x10106, 0x2, 0x0)
r3 = bpf$MAP_CREATE(0x0, &(0x7f00000000c0)=@base={0x1b, 0x0, 0x0, 0x8000}, 0x48)
bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x0, 0xc, &(0x7f0000000240)=ANY=[@ANYBLOB="1800000000000000000000000000000018120000", @ANYRES32=r3, @ANYBLOB="0000000000000000b7080000000000007b8af8ff00000000bfa200000000000007020000f8ffffffb703000008000000b704000002010000850000004300000095"], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
r4 = bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x11, 0xc, &(0x7f0000000240)=ANY=[], &(0x7f0000000200)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f0000000300)={&(0x7f0000000000)='sched_switch\x00', r4}, 0x10)
mkdirat(0xffffffffffffff9c, &(0x7f0000000000)='./file0\x00', 0x0)
bpf$MAP_CREATE(0x0, &(0x7f0000000640)=@base={0x17, 0x0, 0x4, 0x0, 0x0, 0x1}, 0x48)
io_setup(0x3ff, &(0x7f0000000500))
io_submit(0x0, 0x0, 0x0)
bpf$PROG_LOAD_XDP(0x5, 0x0, 0x0)
pipe2$9p(&(0x7f0000000240)={<r5=>0xffffffffffffffff}, 0x0)
dup(0xffffffffffffffff)
mount$9p_fd(0x0, &(0x7f0000000040)='./file0\x00', &(0x7f0000000b80), 0x0, &(0x7f0000000300)=ANY=[@ANYBLOB='trans=fd,rfdno=', @ANYRESHEX=r5])

executing program 1:
syz_mount_image$iso9660(&(0x7f0000000200), &(0x7f0000000000)='./file1\x00', 0x2008c16, &(0x7f0000000700)={[{@check_relaxed}, {@iocharset={'iocharset', 0x3d, 'cp860'}}, {@map_off}, {@map_normal}, {@nocompress}, {@check_strict}, {@check_strict}, {@cruft}, {@mode={'mode', 0x3d, 0x7}}, {@map_off}, {}, {@check_strict}, {@iocharset={'iocharset', 0x3d, 'maccenteuro'}}, {@unhide}, {@overriderock}]}, 0x3, 0x9f5, &(0x7f0000000900)="$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")
syz_mount_image$ext4(&(0x7f0000000440)='ext4\x00', &(0x7f0000000480)='./file0\x00', 0x0, &(0x7f0000000000)={[{@inode_readahead_blks={'inode_readahead_blks', 0x3d, 0x100000}}, {@bh}, {@mblk_io_submit}, {@test_dummy_encryption}, {@jqfmt_vfsv0}, {@usrjquota, 0x2e}], [], 0x2e}, 0x84, 0x46f, &(0x7f0000000580)="$eJzs289vFFUcAPDvbLvlt62IP/ihVtHY+KOlBZWDF40mXExM9IDHWgpBCjW0JkKIVGPwaPgL1KOJf4EnvRj1pPGqiRcTY0IMF9GDGTO7M7C0u+v+ahfczycZeG/mTd/7zszbfTNvJ4CBNZ79k0Rsj4ifRiJGq9mbC4xX/7t29cLcX1cvzCWRpq/+kVTK/Xn1wlxRtNhvW56ZKEWUPkhib516l86dPzW7sDB/Ns9PLZ9+a2rp3PmnTp6ePTF/Yv7MzOHDhw5OP/vMzNM9iXNH1tY97y7u233k9csvzx29/Ma3n2frt+fba+OoGuu6zvEYv/lY1ng04tc0Tbuu41axoyadDPexIbRlKCKy01XO+n+MxlDcOHmj8dL7fW0csK7SNE03rVk7VCRWUuB/LIl+twDoj+KLPrv/LZYNHH703ZXnqzdAWdzX8qW6ZThKeZnyqvvbXhqPiKMrf3+cLVH3OQQAQG99mY1/nqw3/ivFPTXl7ojq3NBYRNwZETsj4q6I2BURd0dUyt4bEfe1Wf/4qvza8c8PWzoKrEXZ+O+5fG7r5vFfMfqLsaE8t6MSfzk5fnJh/kB+TCaivCnLTzep46sXf/yo0bba8V+2ZPUXY8G8Hb8Pr3pAd2x2ebabmGtdeS9iz3C9+JPrMwFJROyOiD0d/P3smJ18/LN9jbb/d/xN9GCeKf004rHq+V+JVfEXkubzk1ObY2H+wFRxVaz13feXXmlUf1fx90B2/rfWvf6vxz+W1M7XLrVfx6WfP2x4T9Pp9T+SvFZJj+Tr3pldXj47HTGSrKxdP3Nj3yJflM/in9hfv//vjPjnk3y/vRGRXcT3R8QDEfFg3vaHIuLhiNjfJP5vXnjkzc7jX19Z/MfaOv/tJ4ZOff1Fo/pbO/+HKqmJfE0rn3+tNrCbYwcAAAC3i1LlN/BJafJ6ulSanKz+hn9XbC0tLC4tP3F88e0zx6q/lR+Lcql40jVa8zx0On82XORnVuUPVp4bp2mabqnkJ+cWF9ZrTh1ozbYG/T/z21C/Wwesu7bm0Rq90QbclryvCYNL/4fB1Wr/L69zO4CN5/sfBle9/n8x4lofmgJsMN//MLj0fxhc+j8MLv0fBlI37/U3S+w80vHuaVe1b84D63D3X9blaDRLDG1gXb1MRKnupnJE3CItbJIo3RrNqCY2RUSrhS92emG3nejzBxMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAECP/BsAAP//cGjokQ==")
bpf$OBJ_GET_MAP(0x7, &(0x7f00000008c0), 0x10)
mount$fuse(0x20000000, &(0x7f0000000400)='./file0\x00', 0x0, 0x223216, 0x0)

[  653.114770][T14650] usb 4-1: Using ep0 maxpacket: 16
executing program 0:
bpf$PROG_LOAD_XDP(0x5, &(0x7f0000000280)={0x17, 0x4, &(0x7f0000000000)=@framed={{}, [@ldst={0x3, 0x0, 0x3, 0x1, 0x0, 0x4}]}, &(0x7f0000000040)='syzkaller\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0xf}, 0x80)

[  653.245059][T14650] usb 4-1: config 0 has an invalid interface number: 8 but max is 0
[  653.253916][T14650] usb 4-1: config 0 has no interface number 0
[  653.270681][T14650] usb 4-1: config 0 interface 8 altsetting 0 endpoint 0x8F has an invalid bInterval 0, changing to 7
executing program 0:
r0 = epoll_create1(0x0)
r1 = syz_open_dev$dri(&(0x7f0000000080), 0x1, 0x0)
r2 = dup2(r1, r1)
read$FUSE(r2, 0x0, 0x0)
ioctl$DRM_IOCTL_WAIT_VBLANK(r2, 0xc018643a, &(0x7f00000001c0)={0x14000000})
epoll_ctl$EPOLL_CTL_ADD(r0, 0x1, r2, &(0x7f0000000140))

[  653.314748][T14650] usb 4-1: config 0 interface 8 altsetting 0 endpoint 0x8F has invalid wMaxPacketSize 0
[  653.348755][T16667] loop1: detected capacity change from 0 to 1764
executing program 4:
r0 = socket$inet6(0xa, 0x2, 0x0)
bind$inet6(r0, &(0x7f0000f5dfe4)={0xa, 0x4e20, 0x0, @empty}, 0x1c)
setsockopt$inet6_int(r0, 0x29, 0x2, &(0x7f00000005c0)=0x7fdf, 0x4)
setsockopt$inet6_IPV6_DSTOPTS(r0, 0x29, 0x3b, &(0x7f0000000080)=ANY=[], 0x8)
setsockopt$inet6_int(r0, 0x29, 0x3a, &(0x7f0000000040)=0x8, 0x4)
recvmmsg(r0, &(0x7f0000004140)=[{{0x0, 0x0, 0x0}}], 0x1, 0x0, 0x0)
sendto$inet6(r0, 0x0, 0x0, 0x0, &(0x7f0000000300)={0xa, 0x4e20, 0x0, @mcast1}, 0x1c)

[  653.475179][T14650] usb 4-1: New USB device found, idVendor=0d8c, idProduct=000e, bcdDevice=8e.8f
[  653.505932][T14650] usb 4-1: New USB device strings: Mfr=0, Product=24, SerialNumber=3
[  653.527934][T16667] iso9660: Corrupted directory entry in block 2 of inode 1920
[  653.537822][T14650] usb 4-1: Product: syz
[  653.546683][T14650] usb 4-1: SerialNumber: syz
[  653.701232][T16678] 9pnet_fd: Insufficient options for proto=fd
executing program 1:
bpf$PROG_LOAD_XDP(0x5, &(0x7f00000001c0)={0xd, 0x4, &(0x7f0000001300)=ANY=[@ANYBLOB="18000000000000000000000000000000611578000000000095"], &(0x7f0000000040)='syzkaller\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x9}, 0x90)

[  654.305293][T14650] usb 4-1: config 0 descriptor??
executing program 4:
openat$ptmx(0xffffffffffffff9c, 0x0, 0x0, 0x0)
ppoll(0x0, 0x0, 0x0, 0x0, 0x0)
r0 = openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000180)='net_prio.prioidx\x00', 0x275a, 0x0)
write$binfmt_script(r0, &(0x7f0000000d40), 0x208e24b)
mmap(&(0x7f0000000000/0xb36000)=nil, 0xb36000, 0x2, 0x28011, r0, 0x0)
r1 = socket$inet(0x2, 0x2, 0x1)
connect$inet(r1, &(0x7f0000000040)={0x2, 0x0, @remote}, 0x10)
sendto$inet(0xffffffffffffffff, &(0x7f0000000100)='\b', 0x1, 0x0, 0x0, 0x0)
sendfile(r1, r0, &(0x7f0000000240)=0x100, 0x2a)

executing program 0:
r0 = socket$inet_udplite(0x2, 0x2, 0x88)
setsockopt$IPT_SO_SET_REPLACE(r0, 0x4000000000000, 0x40, &(0x7f0000000000)=@raw={'raw\x00', 0x41, 0x3, 0x3d0, 0x0, 0x19, 0x0, 0x260, 0x0, 0x338, 0x1f0, 0x1f0, 0x338, 0x1f0, 0x3, 0x0, {[{{@ip={@loopback, @dev, 0x0, 0x0, 'wlan1\x00', 'wg1\x00'}, 0x0, 0x1f8, 0x260, 0x0, {0x0, 0xffffffffa0028000}, [@common=@unspec=@quota={{0x38}, {0x9}}, @common=@inet=@hashlimit2={{0x150}, {'macsec0\x00'}}]}, @unspec=@CT1={0x68, 'CT\x00', 0x1, {0x0, 0x0, 0x0, 0x0, 'pptp\x00', 'syz0\x00'}}}, {{@ip={@empty, @empty, 0x0, 0x0, 'batadv_slave_0\x00', 'netpci0\x00'}, 0x0, 0x70, 0xd8}, @unspec=@CT1={0x68, 'CT\x00', 0x1, {0x0, 0x0, 0x0, 0x0, 'snmp\x00', 'syz0\x00'}}}], {{'\x00', 0x0, 0x70, 0x98}, {0x28, '\x00', 0x4}}}}, 0x430)

[  654.368129][T14650] cm109 4-1:0.8: invalid payload size 0, expected 4
[  654.412078][T14650] input: CM109 USB driver as /devices/platform/dummy_hcd.3/usb4/4-1/4-1:0.8/input/input26
executing program 2:
prctl$PR_SET_SECCOMP(0x16, 0x2, &(0x7f0000000180)={0x1, &(0x7f0000000040)=[{0x6, 0x0, 0x0, 0x7ffc0001}]})
renameat2(0xffffffffffffffff, 0x0, 0xffffffffffffffff, 0x0, 0x0)

executing program 1:
r0 = socket$inet6_tcp(0xa, 0x1, 0x0)
setsockopt$inet6_buf(r0, 0x29, 0x6, &(0x7f00000008c0)="10", 0x1)
sendto$inet6(0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0)
sendmmsg$inet6(r0, &(0x7f00000001c0)=[{{&(0x7f0000000040)={0xa, 0x0, 0x0, @dev, 0x8}, 0x1c, 0x0}}], 0x1, 0x20000000)

executing program 0:
r0 = socket$nl_generic(0x10, 0x3, 0x10)
r1 = syz_genetlink_get_family_id$nl80211(&(0x7f0000000080), 0xffffffffffffffff)
ioctl$sock_SIOCGIFINDEX_80211(r0, 0x8933, &(0x7f00000000c0)={'wlan1\x00', <r2=>0x0})
sendmsg$NL80211_CMD_SET_STATION(r0, &(0x7f00000002c0)={0x0, 0x0, &(0x7f0000000100)={&(0x7f0000000400)={0x34, r1, 0x1, 0x0, 0x0, {{}, {@val={0x8, 0x3, r2}, @void}}, [@NL80211_ATTR_STA_FLAGS2={0xc, 0x43, {0x8001}}, @NL80211_ATTR_MAC={0xa}]}, 0x34}}, 0x0)

[  654.679781][T16645] UDC core: USB Raw Gadget: couldn't find an available UDC or it's busy
[  654.683311][   T29] kauditd_printk_skb: 12 callbacks suppressed
[  654.683329][   T29] audit: type=1326 audit(1715377334.204:1007): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=_ pid=16688 comm="syz-executor.2" exe="/root/syz-executor.2" sig=0 arch=c000003e syscall=202 compat=0 ip=0x7f9b3347dd69 code=0x7ffc0000
[  654.702226][T16645] misc raw-gadget: fail, usb_gadget_register_driver returned -16
executing program 2:
r0 = socket$rxrpc(0x21, 0x2, 0x2)
bind$rxrpc(r0, &(0x7f0000000340)=@in4={0x21, 0x3, 0x2, 0x10, {0x2, 0x0, @local}}, 0x24)
bind$rxrpc(r0, &(0x7f0000001280)=@in4={0x21, 0x4, 0x2, 0x10, {0x2, 0x0, @local}}, 0x24)
listen(r0, 0x0)

[  654.753548][   T29] audit: type=1326 audit(1715377334.204:1008): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=_ pid=16688 comm="syz-executor.2" exe="/root/syz-executor.2" sig=0 arch=c000003e syscall=202 compat=0 ip=0x7f9b3347dd69 code=0x7ffc0000
[  654.776307][   T29] audit: type=1326 audit(1715377334.244:1009): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=_ pid=16688 comm="syz-executor.2" exe="/root/syz-executor.2" sig=0 arch=c000003e syscall=316 compat=0 ip=0x7f9b3347dd69 code=0x7ffc0000
executing program 0:
r0 = bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x3, 0xc, &(0x7f0000000000)=@framed={{}, [@call={0x85, 0x0, 0x0, 0x61}, @printk={@s, {}, {}, {}, {}, {}, {0x85, 0x0, 0x0, 0x71}}]}, &(0x7f0000000200)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_PROG_TEST_RUN(0xa, &(0x7f0000000180)={0xffffffffffffffff, 0x18000000000002a0, 0xe, 0x0, &(0x7f00000002c0)="b9ff03076003008cb89e08f086dd", 0x0, 0x0, 0x60000000, 0x0, 0x0, 0x0, 0x0}, 0x50)
bpf$BPF_PROG_TEST_RUN(0xa, &(0x7f0000000240)={r0, 0x0, 0x10, 0x10, &(0x7f00000002c0)="0000ffffffffa000", &(0x7f0000000300)=""/8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x4c)

[  654.804170][   T29] audit: type=1326 audit(1715377334.244:1010): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=_ pid=16688 comm="syz-executor.2" exe="/root/syz-executor.2" sig=0 arch=c000003e syscall=202 compat=0 ip=0x7f9b3347dd69 code=0x7ffc0000
executing program 2:
r0 = syz_init_net_socket$bt_l2cap(0x1f, 0x5, 0x0)
setsockopt$bt_l2cap_L2CAP_LM(r0, 0x6, 0x3, &(0x7f00000001c0)=0x25, 0x4)

[  654.869106][   T29] audit: type=1326 audit(1715377334.244:1011): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=_ pid=16688 comm="syz-executor.2" exe="/root/syz-executor.2" sig=0 arch=c000003e syscall=202 compat=0 ip=0x7f9b3347dd69 code=0x7ffc0000
executing program 0:
bpf$BPF_LINK_CREATE(0x1c, 0x0, 0x0)
r0 = socket$inet6(0xa, 0x3, 0x7)
connect$inet6(r0, &(0x7f00000000c0)={0xa, 0x0, 0x0, @loopback}, 0x1c)
prlimit64(0x0, 0xe, &(0x7f0000000140)={0x8, 0x100008b}, 0x0)
sched_setscheduler(0x0, 0x1, &(0x7f0000000080)=0x7)
r1 = getpid()
sched_setscheduler(r1, 0x1, &(0x7f0000000100)=0x5)
mmap(&(0x7f0000000000/0xb36000)=nil, 0xb36000, 0xb635773f06ebbeee, 0x10, 0xffffffffffffffff, 0x0)
socketpair$unix(0x1, 0x3, 0x0, &(0x7f0000000240)={<r2=>0xffffffffffffffff, <r3=>0xffffffffffffffff})
connect$unix(r2, &(0x7f000057eff8)=@abs, 0x6e)
sendmmsg$unix(r3, &(0x7f00000bd000), 0x318, 0x0)
recvmmsg(r2, &(0x7f00000000c0), 0x10106, 0x2, 0x0)
sendmmsg(r0, &(0x7f0000000480), 0x2e9, 0xfc00)

executing program 2:
syz_mount_image$iso9660(&(0x7f0000000200), &(0x7f0000000000)='./file1\x00', 0x2008c16, &(0x7f0000000700)={[{@check_relaxed}, {@iocharset={'iocharset', 0x3d, 'cp860'}}, {@map_off}, {@map_normal}, {@nocompress}, {@check_strict}, {@check_strict}, {@cruft}, {@mode={'mode', 0x3d, 0x7}}, {@map_off}, {}, {@check_strict}, {@iocharset={'iocharset', 0x3d, 'maccenteuro'}}, {@unhide}, {@overriderock}]}, 0x3, 0x9f5, &(0x7f0000000900)="$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")
syz_mount_image$ext4(&(0x7f0000000440)='ext4\x00', &(0x7f0000000480)='./file0\x00', 0x0, &(0x7f0000000000)={[{@inode_readahead_blks={'inode_readahead_blks', 0x3d, 0x100000}}, {@bh}, {@mblk_io_submit}, {@test_dummy_encryption}, {@jqfmt_vfsv0}, {@usrjquota, 0x2e}], [], 0x2e}, 0x84, 0x46f, &(0x7f0000000580)="$eJzs289vFFUcAPDvbLvlt62IP/ihVtHY+KOlBZWDF40mXExM9IDHWgpBCjW0JkKIVGPwaPgL1KOJf4EnvRj1pPGqiRcTY0IMF9GDGTO7M7C0u+v+ahfczycZeG/mTd/7zszbfTNvJ4CBNZ79k0Rsj4ifRiJGq9mbC4xX/7t29cLcX1cvzCWRpq/+kVTK/Xn1wlxRtNhvW56ZKEWUPkhib516l86dPzW7sDB/Ns9PLZ9+a2rp3PmnTp6ePTF/Yv7MzOHDhw5OP/vMzNM9iXNH1tY97y7u233k9csvzx29/Ma3n2frt+fba+OoGuu6zvEYv/lY1ng04tc0Tbuu41axoyadDPexIbRlKCKy01XO+n+MxlDcOHmj8dL7fW0csK7SNE03rVk7VCRWUuB/LIl+twDoj+KLPrv/LZYNHH703ZXnqzdAWdzX8qW6ZThKeZnyqvvbXhqPiKMrf3+cLVH3OQQAQG99mY1/nqw3/ivFPTXl7ojq3NBYRNwZETsj4q6I2BURd0dUyt4bEfe1Wf/4qvza8c8PWzoKrEXZ+O+5fG7r5vFfMfqLsaE8t6MSfzk5fnJh/kB+TCaivCnLTzep46sXf/yo0bba8V+2ZPUXY8G8Hb8Pr3pAd2x2ebabmGtdeS9iz3C9+JPrMwFJROyOiD0d/P3smJ18/LN9jbb/d/xN9GCeKf004rHq+V+JVfEXkubzk1ObY2H+wFRxVaz13feXXmlUf1fx90B2/rfWvf6vxz+W1M7XLrVfx6WfP2x4T9Pp9T+SvFZJj+Tr3pldXj47HTGSrKxdP3Nj3yJflM/in9hfv//vjPjnk3y/vRGRXcT3R8QDEfFg3vaHIuLhiNjfJP5vXnjkzc7jX19Z/MfaOv/tJ4ZOff1Fo/pbO/+HKqmJfE0rn3+tNrCbYwcAAAC3i1LlN/BJafJ6ulSanKz+hn9XbC0tLC4tP3F88e0zx6q/lR+Lcql40jVa8zx0On82XORnVuUPVp4bp2mabqnkJ+cWF9ZrTh1ozbYG/T/z21C/Wwesu7bm0Rq90QbclryvCYNL/4fB1Wr/L69zO4CN5/sfBle9/n8x4lofmgJsMN//MLj0fxhc+j8MLv0fBlI37/U3S+w80vHuaVe1b84D63D3X9blaDRLDG1gXb1MRKnupnJE3CItbJIo3RrNqCY2RUSrhS92emG3nejzBxMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAECP/BsAAP//cGjokQ==")
bpf$OBJ_GET_MAP(0x7, &(0x7f00000008c0), 0x10)
mount$fuse(0x20000000, &(0x7f0000000400)='./file0\x00', 0x0, 0x223216, 0x0)

[  655.129997][T16706] loop2: detected capacity change from 0 to 1764
executing program 4:
r0 = bpf$MAP_CREATE(0x0, &(0x7f00000000c0)=@base={0x1b, 0x0, 0x0, 0x8000}, 0x48)
r1 = openat$vcsu(0xffffffffffffff9c, &(0x7f0000000000), 0x0, 0x0)
poll(&(0x7f0000000200)=[{r1}], 0x1, 0x0)
read$FUSE(r1, &(0x7f0000006440)={0x2020}, 0x2020)
r2 = bpf$PROG_LOAD(0x5, &(0x7f0000000340)={0x6, 0x1c, &(0x7f0000000400)=ANY=[@ANYBLOB="1800000000000000000000000000000018110000", @ANYRES32=r0, @ANYBLOB="0000000000000000b702000014000000b7030000000000008500000083000000bf090000000000005509010000000000950000000000000018110000", @ANYRES32=r0, @ANYBLOB="0000000000000000b702000000000700850000001700000018110000", @ANYRES32=r0, @ANYBLOB="0000000000000000b7080000000000007b8af8ff00000000bfa200000000000007020000f8ffffffb703000008000000b7040000020000008500000082000000bf91000000000000b7020000000000008500000085000000b70000000000000095"], &(0x7f0000000080)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_PROG_TEST_RUN(0xa, &(0x7f0000000240)={r2, 0xfca804a0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x50)
getsockopt$inet6_IPV6_IPSEC_POLICY(0xffffffffffffffff, 0x29, 0x22, &(0x7f0000000500)={{{@in=@dev, @in=@multicast2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, <r3=>0x0}}, {{@in=@remote}, 0x0, @in=@local}}, &(0x7f0000000000)=0xe8)
syz_mount_image$ext4(&(0x7f0000000180)='ext4\x00', &(0x7f0000000080)='./file0\x00', 0x0, &(0x7f0000000600)={[], [{@euid_gt={'euid>', r3}}, {@uid_lt={'uid<', r3}}, {@dont_hash}, {@obj_user={'obj_user', 0x3d, '\'$5$/\'-'}}]}, 0x1, 0x46a, &(0x7f0000000980)="$eJzs289vFFUcAPDvzLZFQWhFFEFUFI2NP1paUDl40WjiQRMTPeCxtoUACzW0JkKIVmPwaEi8G48m/gWe9GLUk4lXvBsSolxAT2tmd6Zsl93tLpRd6H4+yTbv7bzpe9+deTNv5s0EMLD2Zn+SiPsi4mJEjNayKyp5oazctSvnZv+9cm42iUrl3b+TarmrV87NFmWL9bbkmfE0Iv0iyStZbfHM2RMz5fL86Tw/uXTyw8nFM2dfOHZy5uj80flT04cOHTww9fJL0y+uS5xZfFd3f7KwZ9eb7194e/bwhQ9+/T7Jv4+GODox3EGZvVng/1SqGpc93U1ld4GtdelkqI8NoSuliBjK9+eLMRqluL7xRuONz/vaOOC2ys5Nm1ovXq4AG1gS/W4B0B/FiT67/i0+PRp63BEuv1q7AMrivpZ/akuGIs3LDDdc366nvRFxePm/b7JP3MR9CACAbv2YjX+ebzb+S6N+jLgtnxsai4j7I2J7RDwQETsi4sGIeCgidkbEw51Ve7xINE4N3Tj+SS/daoztZOO/V/K5rdXjv2L0F2OlPLe1Gv9wcuRYeX5//puMx/CmLD/Vpo6fXv/jq1bL6sd/2Ser//CqyaX00lDDDbq5maWZjiagOnD5s4jdQ83iT1ZmApKI2BURu7v719uKxLFnv9vTqlDT+POx8JrWYZ6p8m3EM7XtvxwN8ReS9vOTk/dEeX7/ZLFX3Oi338+/06r+W4p/HWTbf/Pq/b+xyFhSP1+72H0d5//8suU1zdrxN9//R5L3qsejkfy7j2eWlk5PRYwkb9XWqv9++vq6Rb4on8U/vq95/9+er5PF/0hEZDvxoxHxWEQ8nrf9iYh4MiL2tYn/l9eeOt5l/Embf7eusvjnmh7/VprQsP27T5RO/PxDq/o72/4Hq6nx/Jvq8W8NnTbwVn47AAAAuFuk1Wfgk3RiJZ2mExO1Z/h3xOa0vLC49NyRhY9OzdWelR+L4bS40zVadz90KlnOnyaO6tX3dH6vuFh+IL9v/HXp3mp+YnahPNfn2GHQbanr/9t3Xu//mb9Kq8uuzIh4vwM2Dv0ZBldj/0/71A6g95z/YXDp/zC49H8YXM36/6cN+VKP2gL0lvM/DK61+n/P3kYCes75HwaX/g8Dqd278cnNv/Iv0d9ELN/+KtI7ItLblRjpoINs6MSNx4oh4wQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOAu9H8AAAD//xjg70M=")
quotactl$Q_QUOTAON(0xffffffff80000200, &(0x7f00000002c0)=@loop={'/dev/loop', 0x0}, 0x0, &(0x7f0000000340)='./file0\x00')
bpf$OBJ_GET_PROG(0x7, &(0x7f0000000140)=@generic={&(0x7f0000000040)='./file0\x00', 0x0, 0x10}, 0x18)

[  656.081609][T14650] usb 4-1: USB disconnect, device number 23
[  656.087649][    C0] cm109 4-1:0.8: cm109_urb_ctl_callback: urb status -71
[  656.087681][    C0] cm109 4-1:0.8: cm109_submit_buzz_toggle: usb_submit_urb (urb_ctl) failed -19
executing program 0:
syz_mount_image$fuse(0x0, &(0x7f0000000140)='./file0\x00', 0x0, 0x0, 0x0, 0x0, 0x0)
pipe2$9p(&(0x7f0000000240)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff}, 0x0)
write$P9_RVERSION(r1, &(0x7f0000000040)=ANY=[@ANYBLOB="1500000065ffff001000000800395032303030"], 0x15)
r2 = dup(r1)
write$FUSE_BMAP(r2, &(0x7f0000000100)={0x18}, 0x18)
write$FUSE_DIRENT(r2, &(0x7f0000000000)=ANY=[@ANYBLOB="58000000000000009fed2788c5532994414b47034801d524faf416638217", @ANYRES32], 0x58)
mount$9p_fd(0x0, &(0x7f0000000180)='./file0\x00', &(0x7f0000000200), 0x0, &(0x7f0000000280)=ANY=[@ANYBLOB='trans=fd,rfdno=', @ANYRESHEX=r0, @ANYBLOB=',wfdno=', @ANYRESHEX=r1])
chdir(&(0x7f0000000100)='./file0\x00')
read$FUSE(r0, &(0x7f0000000300)={0x2020}, 0x2020)
openat$cgroup_ro(0xffffffffffffff9c, &(0x7f0000000040)='memory.events\x00', 0x275a, 0x0)

executing program 1:
sendmsg$nl_route(0xffffffffffffffff, &(0x7f0000000340)={0x0, 0x0, &(0x7f0000000300)={&(0x7f0000000140)=ANY=[@ANYBLOB="340100001900000000000000000000001d0100001e"], 0x134}}, 0x0)
r0 = openat$sndseq(0xffffffffffffff9c, &(0x7f0000000040), 0x62181)
ioctl$SNDRV_SEQ_IOCTL_CREATE_QUEUE(r0, 0xc08c5332, &(0x7f00000001c0)={0x0, 0x0, 0x0, 'queue1\x00'})
write$sndseq(r0, &(0x7f0000000000)=[{0x84, 0x77, 0x0, 0x0, @time={0x0, 0xffffff2f}, {}, {}, @raw32}], 0xffca)
r1 = openat$sndseq(0xffffffffffffff9c, &(0x7f00000018c0), 0xa8c01)
write$sndseq(r1, &(0x7f0000000080)=[{0x1e, 0x0, 0x0, 0xfd, @time, {}, {}, @result}], 0x1c)

[  656.122421][T14650] cm109 4-1:0.8: cm109_toggle_buzzer_sync: usb_control_msg() failed -19
[  656.195071][T16706] iso9660: Corrupted directory entry in block 2 of inode 1920
executing program 2:
creat(&(0x7f0000000240)='./file0\x00', 0x0)
pipe2$9p(&(0x7f0000001900)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff}, 0x0)
write$P9_RVERSION(r1, &(0x7f0000000500)=ANY=[@ANYBLOB="1500000065ffff048000000800395032303030"], 0x15)
r2 = dup(r1)
write$FUSE_BMAP(r2, &(0x7f0000000100)={0x18}, 0x18)
write$FUSE_NOTIFY_RETRIEVE(r2, &(0x7f00000000c0)={0x14c}, 0x137)
mount$9p_fd(0x0, &(0x7f0000000000)='./file0\x00', &(0x7f0000000040), 0x0, &(0x7f0000000280)={'trans=fd,', {'rfdno', 0x3d, r0}, 0x2c, {'wfdno', 0x3d, r2}, 0x2c, {[{@cache_mmap}], [], 0x6b}})
chmod(&(0x7f0000000140)='./file0\x00', 0x0)
r3 = creat(&(0x7f0000000300)='./file0\x00', 0x0)
write$FUSE_LSEEK(r3, &(0x7f0000000380)={0x18}, 0xfdef)
lchown(&(0x7f0000000180)='./file0\x00', 0x0, 0x0)

executing program 0:
prlimit64(0x0, 0xe, &(0x7f0000000140)={0x8, 0x8b}, 0x0)
sched_setscheduler(0x0, 0x1, &(0x7f0000000080)=0x7)
r0 = getpid()
sched_setaffinity(0x0, 0x8, &(0x7f00000002c0)=0x2)
sched_setscheduler(r0, 0x2, &(0x7f0000000200)=0x4)
mmap(&(0x7f0000000000/0xb36000)=nil, 0xb36000, 0xb635773f06ebbeee, 0x8031, 0xffffffffffffffff, 0x0)
socketpair$unix(0x1, 0x3, 0x0, &(0x7f0000000380)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff})
connect$unix(r1, &(0x7f00000003c0)=@abs, 0x6e)
sendmmsg$unix(r2, &(0x7f0000000000), 0x651, 0x0)
recvmmsg(r1, &(0x7f00000000c0), 0x10106, 0x2, 0x0)
r3 = bpf$MAP_CREATE(0x0, &(0x7f00000000c0)=@base={0x1b, 0x0, 0x0, 0x8000}, 0x48)
bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x0, 0xc, &(0x7f0000000240)=ANY=[@ANYBLOB="1800000000000000000000000000000018120000", @ANYRES32=r3, @ANYBLOB="0000000000000000b7080000000000007b8af8ff00000000bfa200000000000007020000f8ffffffb703000008000000b704000002010000850000004300000095"], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
r4 = bpf$PROG_LOAD(0x5, &(0x7f00000000c0)={0x11, 0xc, &(0x7f0000000240)=ANY=[], &(0x7f0000000200)='GPL\x00', 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', 0x0, 0x0, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x90)
bpf$BPF_RAW_TRACEPOINT_OPEN(0x11, &(0x7f0000000300)={&(0x7f0000000000)='sched_switch\x00', r4}, 0x10)
mkdirat(0xffffffffffffff9c, &(0x7f0000000000)='./file0\x00', 0x0)
bpf$MAP_CREATE(0x0, &(0x7f0000000640)=@base={0x17, 0x0, 0x4, 0x0, 0x0, 0x1}, 0x48)
io_setup(0x3ff, &(0x7f0000000500))
io_submit(0x0, 0x0, 0x0)
bpf$PROG_LOAD_XDP(0x5, 0x0, 0x0)
pipe2$9p(&(0x7f0000000240)={<r5=>0xffffffffffffffff}, 0x0)
dup(0xffffffffffffffff)
mount$9p_fd(0x0, &(0x7f0000000040)='./file0\x00', &(0x7f0000000b80), 0x0, &(0x7f0000000300)=ANY=[@ANYBLOB='trans=fd,rfdno=', @ANYRESHEX=r5])

[  656.326016][T16714] loop4: detected capacity change from 0 to 512
[  656.351051][T16714] ext4: Unknown parameter 'euid>00000000000000000000'
executing program 1:
r0 = socket$inet6(0xa, 0x2, 0x0)
bind$inet6(r0, &(0x7f0000f5dfe4)={0xa, 0x4e20, 0x0, @empty}, 0x1c)
setsockopt$inet6_int(r0, 0x29, 0x2, &(0x7f00000005c0)=0x7fdf, 0x4)
setsockopt$inet6_IPV6_DSTOPTS(r0, 0x29, 0x3b, &(0x7f0000000080)=ANY=[], 0x8)
setsockopt$inet6_int(r0, 0x29, 0x3a, &(0x7f0000000040)=0x8, 0x4)
recvmmsg(r0, &(0x7f0000004140)=[{{0x0, 0x0, 0x0}}], 0x1, 0x0, 0x0)
sendto$inet6(r0, 0x0, 0x0, 0x0, &(0x7f0000000300)={0xa, 0x4e20, 0x0, @mcast1}, 0x1c)

executing program 4:
r0 = socket$nl_generic(0x10, 0x3, 0x10)
r1 = syz_genetlink_get_family_id$ethtool(&(0x7f0000000480), 0xffffffffffffffff)
sendmsg$ETHTOOL_MSG_PRIVFLAGS_SET(r0, &(0x7f0000000b80)={0x0, 0x0, &(0x7f00000000c0)={&(0x7f0000000240)=ANY=[@ANYBLOB=',\x00\x00\x00', @ANYRES16=r1, @ANYBLOB="010000000000000000002100000018000180140002"], 0x2c}}, 0x0)

executing program 1:
socket$inet_icmp_raw(0x2, 0x3, 0x1)
socket$inet_icmp_raw(0x2, 0x3, 0x1)
syz_emit_ethernet(0x46, &(0x7f0000000000)={@link_local={0x3}, @multicast, @void, {@ipv4={0x800, @icmp={{0x5, 0x4, 0x0, 0x0, 0x38, 0x0, 0x0, 0x0, 0x1, 0x0, @initdev={0xac, 0x1e, 0x0, 0x0}, @local}, @time_exceeded={0x5, 0x0, 0x0, 0x12, 0x0, 0x3f18, {0x5, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, @local, @dev}, "00186371ae9b1c03"}}}}}, 0x0)

[  657.002993][T16727] 9pnet_fd: Insufficient options for proto=fd
[  657.065900][T14884] 9pnet: Found fid 1 not clunked
[  657.131960][T14884] ==================================================================
[  657.140079][T14884] BUG: KASAN: slab-use-after-free in p9_client_destroy+0x183/0x660
[  657.148087][T14884] Read of size 8 at addr ffff88801e478d00 by task syz-executor.2/14884
[  657.156360][T14884]
[  657.158693][T14884] CPU: 1 PID: 14884 Comm: syz-executor.2 Not tainted 6.9.0-rc7-syzkaller-00136-gf4345f05c0df #0
[  657.169113][T14884] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 04/02/2024
[  657.179177][T14884] Call Trace:
[  657.182467][T14884]  <TASK>
[  657.185414][T14884]  dump_stack_lvl+0x241/0x360
[  657.190194][T14884]  ? __pfx_dump_stack_lvl+0x10/0x10
[  657.195439][T14884]  ? __pfx__printk+0x10/0x10
[  657.200138][T14884]  ? _printk+0xd5/0x120
[  657.204323][T14884]  ? __virt_addr_valid+0x183/0x520
[  657.209456][T14884]  ? __virt_addr_valid+0x183/0x520
[  657.214608][T14884]  print_report+0x169/0x550
[  657.219152][T14884]  ? __virt_addr_valid+0x183/0x520
[  657.224295][T14884]  ? __virt_addr_valid+0x183/0x520
[  657.229443][T14884]  ? __virt_addr_valid+0x44e/0x520
[  657.234587][T14884]  ? __phys_addr+0xba/0x170
[  657.239121][T14884]  ? p9_client_destroy+0x183/0x660
[  657.244253][T14884]  kasan_report+0x143/0x180
[  657.248796][T14884]  ? p9_client_destroy+0x183/0x660
[  657.253942][T14884]  p9_client_destroy+0x183/0x660
[  657.258912][T14884]  ? __pfx_p9_client_destroy+0x10/0x10
[  657.264406][T14884]  ? do_raw_spin_unlock+0x13c/0x8b0
[  657.269669][T14884]  v9fs_session_close+0x51/0x210
[  657.274639][T14884]  v9fs_kill_super+0x5c/0x90
[  657.279245][T14884]  deactivate_locked_super+0xc4/0x130
[  657.284631][T14884]  cleanup_mnt+0x426/0x4c0
[  657.289083][T14884]  ? _raw_spin_unlock_irq+0x23/0x50
[  657.294383][T14884]  task_work_run+0x24f/0x310
[  657.299049][T14884]  ? __pfx_task_work_run+0x10/0x10
[  657.304179][T14884]  ? __x64_sys_umount+0x126/0x170
[  657.309239][T14884]  ? syscall_exit_to_user_mode+0xa3/0x370
[  657.314989][T14884]  syscall_exit_to_user_mode+0x168/0x370
[  657.320656][T14884]  do_syscall_64+0x102/0x240
[  657.325309][T14884]  ? clear_bhb_loop+0x35/0x90
[  657.330207][T14884]  entry_SYSCALL_64_after_hwframe+0x77/0x7f
[  657.336200][T14884] RIP: 0033:0x7f9b3347f097
[  657.340646][T14884] Code: b0 ff ff ff f7 d8 64 89 01 48 83 c8 ff c3 0f 1f 44 00 00 31 f6 e9 09 00 00 00 66 0f 1f 84 00 00 00 00 00 b8 a6 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 01 c3 48 c7 c2 b0 ff ff ff f7 d8 64 89 02 b8
[  657.360287][T14884] RSP: 002b:00007fff26a7f1a8 EFLAGS: 00000246 ORIG_RAX: 00000000000000a6
[  657.368743][T14884] RAX: 0000000000000000 RBX: 0000000000000000 RCX: 00007f9b3347f097
[  657.376736][T14884] RDX: 0000000000000000 RSI: 0000000000000009 RDI: 00007fff26a7f260
[  657.384721][T14884] RBP: 00007fff26a7f260 R08: 0000000000000000 R09: 0000000000000000
[  657.392712][T14884] R10: 00000000ffffffff R11: 0000000000000246 R12: 00007fff26a80320
[  657.400710][T14884] R13: 00007f9b334c9336 R14: 00000000000a0428 R15: 000000000000000b
[  657.408742][T14884]  </TASK>
[  657.411778][T14884]
[  657.414110][T14884] Allocated by task 16717:
[  657.418557][T14884]  kasan_save_track+0x3f/0x80
[  657.423256][T14884]  __kasan_kmalloc+0x98/0xb0
[  657.427868][T14884]  kmalloc_trace+0x1db/0x370
[  657.432493][T14884]  p9_fid_create+0x4f/0x230
[  657.437026][T14884]  p9_client_walk+0x103/0x690
[  657.441730][T14884]  v9fs_file_open+0x285/0xa60
[  657.446434][T14884]  do_dentry_open+0x907/0x15a0
[  657.451225][T14884]  path_openat+0x2860/0x3240
[  657.455843][T14884]  do_filp_open+0x235/0x490
[  657.460377][T14884]  do_sys_openat2+0x13e/0x1d0
[  657.465090][T14884]  __x64_sys_creat+0x123/0x170
[  657.469889][T14884]  do_syscall_64+0xf5/0x240
[  657.474431][T14884]  entry_SYSCALL_64_after_hwframe+0x77/0x7f
[  657.480360][T14884]
[  657.482698][T14884] Freed by task 140:
[  657.486601][T14884]  kasan_save_track+0x3f/0x80
[  657.491302][T14884]  kasan_save_free_info+0x40/0x50
[  657.496370][T14884]  poison_slab_object+0xa6/0xe0
[  657.501251][T14884]  __kasan_slab_free+0x37/0x60
[  657.506030][T14884]  kfree+0x153/0x3b0
[  657.509952][T14884]  p9_client_clunk+0x1ce/0x260
[  657.514741][T14884]  netfs_free_request+0x244/0x600
[  657.519823][T14884]  v9fs_upload_to_server_worker+0x200/0x3e0
[  657.525765][T14884]  process_scheduled_works+0xa10/0x17c0
[  657.531351][T14884]  worker_thread+0x86d/0xd70
[  657.535963][T14884]  kthread+0x2f0/0x390
[  657.540055][T14884]  ret_from_fork+0x4b/0x80
[  657.544536][T14884]  ret_from_fork_asm+0x1a/0x30
[  657.549349][T14884]
[  657.551688][T14884] The buggy address belongs to the object at ffff88801e478d00
[  657.551688][T14884]  which belongs to the cache kmalloc-96 of size 96
[  657.565590][T14884] The buggy address is located 0 bytes inside of
[  657.565590][T14884]  freed 96-byte region [ffff88801e478d00, ffff88801e478d60)
[  657.579184][T14884]
[  657.581526][T14884] The buggy address belongs to the physical page:
[  657.587948][T14884] page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x1e478
[  657.596722][T14884] flags: 0xfff00000000800(slab|node=0|zone=1|lastcpupid=0x7ff)
[  657.604288][T14884] page_type: 0xffffffff()
[  657.608640][T14884] raw: 00fff00000000800 ffff888015041780 ffffea0000b68440 dead000000000002
[  657.617244][T14884] raw: 0000000000000000 0000000000200020 00000001ffffffff 0000000000000000
[  657.625842][T14884] page dumped because: kasan: bad access detected
[  657.632289][T14884] page_owner tracks the page as allocated
[  657.638017][T14884] page last allocated via order 0, migratetype Unmovable, gfp_mask 0x112cc0(GFP_USER|__GFP_NOWARN|__GFP_NORETRY), pid 5148, tgid 2075898714 (kworker/0:5), ts 5148, free_ts 79305822594
[  657.656102][T14884]  post_alloc_hook+0x1ea/0x210
[  657.660898][T14884]  get_page_from_freelist+0x3410/0x35b0
[  657.666479][T14884]  __alloc_pages+0x256/0x6c0
[  657.671120][T14884]  alloc_slab_page+0x5f/0x160
[  657.675830][T14884]  new_slab+0x84/0x2f0
[  657.679927][T14884]  ___slab_alloc+0xc73/0x1260
[  657.684629][T14884]  kmalloc_trace+0x269/0x370
[  657.689258][T14884]  nsim_fib_event_work+0x19c2/0x4130
[  657.694660][T14884]  process_scheduled_works+0xa10/0x17c0
[  657.700230][T14884]  worker_thread+0x86d/0xd70
[  657.704847][T14884]  kthread+0x2f0/0x390
[  657.708939][T14884]  ret_from_fork+0x4b/0x80
[  657.713381][T14884]  ret_from_fork_asm+0x1a/0x30
[  657.718169][T14884] page last free pid 927 tgid 927 stack trace:
[  657.724345][T14884]  free_unref_page_prepare+0x97b/0xaa0
[  657.729836][T14884]  free_unref_page+0x37/0x3f0
[  657.734546][T14884]  __put_partials+0xeb/0x130
[  657.739152][T14884]  put_cpu_partial+0x17c/0x250
[  657.743930][T14884]  __slab_free+0x2ea/0x3d0
[  657.748360][T14884]  qlist_free_all+0x5e/0xc0
[  657.752879][T14884]  kasan_quarantine_reduce+0x14f/0x170
[  657.758357][T14884]  __kasan_slab_alloc+0x23/0x80
[  657.763223][T14884]  kmem_cache_alloc+0x174/0x350
[  657.768096][T14884]  xfs_trans_alloc+0x81/0x830
[  657.772812][T14884]  xfs_setfilesize+0xd7/0x4e0
[  657.777528][T14884]  xfs_end_ioend+0x317/0x470
[  657.782131][T14884]  xfs_end_io+0x2e5/0x380
[  657.786471][T14884]  process_scheduled_works+0xa10/0x17c0
[  657.792028][T14884]  worker_thread+0x86d/0xd70
[  657.796636][T14884]  kthread+0x2f0/0x390
[  657.800725][T14884]
[  657.803072][T14884] Memory state around the buggy address:
[  657.808713][T14884]  ffff88801e478c00: fa fb fb fb fb fb fb fb fb fb fb fb fc fc fc fc
[  657.816795][T14884]  ffff88801e478c80: fa fb fb fb fb fb fb fb fb fb fb fb fc fc fc fc
[  657.824868][T14884] >ffff88801e478d00: fa fb fb fb fb fb fb fb fb fb fb fb fc fc fc fc
[  657.832933][T14884]                    ^
[  657.837004][T14884]  ffff88801e478d80: fa fb fb fb fb fb fb fb fb fb fb fb fc fc fc fc
[  657.845074][T14884]  ffff88801e478e00: 00 00 00 00 00 00 00 00 00 00 00 00 fc fc fc fc
[  657.853141][T14884] ==================================================================
[  657.861285][    C1] vkms_vblank_simulate: vblank timer overrun
[  658.212322][T14884] Kernel panic - not syncing: KASAN: panic_on_warn set ...
[  658.219602][T14884] CPU: 0 PID: 14884 Comm: syz-executor.2 Not tainted 6.9.0-rc7-syzkaller-00136-gf4345f05c0df #0
[  658.230066][T14884] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 04/02/2024
[  658.240147][T14884] Call Trace:
[  658.243445][T14884]  <TASK>
[  658.246414][T14884]  dump_stack_lvl+0x241/0x360
[  658.251139][T14884]  ? __pfx_dump_stack_lvl+0x10/0x10
[  658.256382][T14884]  ? __pfx__printk+0x10/0x10
[  658.261008][T14884]  ? preempt_schedule+0xe1/0xf0
[  658.265950][T14884]  ? vscnprintf+0x5d/0x90
[  658.270333][T14884]  panic+0x349/0x860
[  658.274264][T14884]  ? check_panic_on_warn+0x21/0xb0
[  658.279397][T14884]  ? __pfx_panic+0x10/0x10
[  658.283841][T14884]  ? _raw_spin_unlock_irqrestore+0x130/0x140
[  658.289853][T14884]  ? __pfx__raw_spin_unlock_irqrestore+0x10/0x10
[  658.296213][T14884]  ? print_report+0x502/0x550
[  658.300921][T14884]  check_panic_on_warn+0x86/0xb0
[  658.305882][T14884]  ? p9_client_destroy+0x183/0x660
[  658.311069][T14884]  end_report+0x77/0x160
[  658.315354][T14884]  kasan_report+0x154/0x180
[  658.319881][T14884]  ? p9_client_destroy+0x183/0x660
[  658.325029][T14884]  p9_client_destroy+0x183/0x660
[  658.329995][T14884]  ? __pfx_p9_client_destroy+0x10/0x10
[  658.335480][T14884]  ? do_raw_spin_unlock+0x13c/0x8b0
[  658.340724][T14884]  v9fs_session_close+0x51/0x210
[  658.345725][T14884]  v9fs_kill_super+0x5c/0x90
[  658.350381][T14884]  deactivate_locked_super+0xc4/0x130
[  658.355787][T14884]  cleanup_mnt+0x426/0x4c0
[  658.360247][T14884]  ? _raw_spin_unlock_irq+0x23/0x50
[  658.365489][T14884]  task_work_run+0x24f/0x310
[  658.370114][T14884]  ? __pfx_task_work_run+0x10/0x10
[  658.375255][T14884]  ? __x64_sys_umount+0x126/0x170
[  658.380305][T14884]  ? syscall_exit_to_user_mode+0xa3/0x370
[  658.386062][T14884]  syscall_exit_to_user_mode+0x168/0x370
[  658.391727][T14884]  do_syscall_64+0x102/0x240
[  658.396351][T14884]  ? clear_bhb_loop+0x35/0x90
[  658.401047][T14884]  entry_SYSCALL_64_after_hwframe+0x77/0x7f
[  658.406970][T14884] RIP: 0033:0x7f9b3347f097
[  658.411400][T14884] Code: b0 ff ff ff f7 d8 64 89 01 48 83 c8 ff c3 0f 1f 44 00 00 31 f6 e9 09 00 00 00 66 0f 1f 84 00 00 00 00 00 b8 a6 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 01 c3 48 c7 c2 b0 ff ff ff f7 d8 64 89 02 b8
[  658.431052][T14884] RSP: 002b:00007fff26a7f1a8 EFLAGS: 00000246 ORIG_RAX: 00000000000000a6
[  658.439492][T14884] RAX: 0000000000000000 RBX: 0000000000000000 RCX: 00007f9b3347f097
[  658.447487][T14884] RDX: 0000000000000000 RSI: 0000000000000009 RDI: 00007fff26a7f260
[  658.455475][T14884] RBP: 00007fff26a7f260 R08: 0000000000000000 R09: 0000000000000000
[  658.463459][T14884] R10: 00000000ffffffff R11: 0000000000000246 R12: 00007fff26a80320
[  658.471484][T14884] R13: 00007f9b334c9336 R14: 00000000000a0428 R15: 000000000000000b
[  658.479498][T14884]  </TASK>
[  658.482898][T14884] Kernel Offset: disabled
[  658.487230][T14884] Rebooting in 86400 seconds..
`

func TestSaveInter(t *testing.T) {
	title := "KASAN: slab-use-after-free in p9_client_destroy"
	pstr := `executing program 4:
r0 = socket$nl_generic(0x10, 0x3, 0x10)
r1 = syz_genetlink_get_family_id$ethtool(&(0x7f0000000480), 0xffffffffffffffff)
sendmsg$ETHTOOL_MSG_PRIVFLAGS_SET(r0, &(0x7f0000000b80)={0x0, 0x0, &(0x7f00000000c0)={&(0x7f0000000240)=ANY=[@ANYBLOB=',\x00\x00\x00', @ANYRES16=r1, @ANYBLOB="010000000000000000002100000018000180140002"], 0x2c}}, 0x0)

`
	ctx := prepareTestCtx(t, example)
	// var rep repro
	ctx.saveInter(title, pstr)
}
