import unittest
import sys
sys.path.append("../plugins/rift_ida_lib/")
from rift_rustlib import get_commithash,get_crates


class TestRiftIdaUtils(unittest.TestCase):

    def test_get_crates(self):

        test_1 = [
            "/home/kali/.cargo/registry/src/index.crates.io-6f17d22bba15001f/clap-3.2.25/src/mkeymap.rs",
            "/rust/deps/miniz_oxide-0.7.4/src/inflate/core.rs",
            ".cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\tokio-1.32.0\\src\\sync\\mpsc\\chan.rs"
        ]
        test_result_1 = ["clap-3.2.25", "miniz_oxide-0.7.4", "tokio-1.32.0"]
        self.assertCountEqual(get_crates(test_1), test_result_1)
        print("[test] get_crates_test_1 success!")

        test_2 = ["/home/kali/.cargo/registry/src/index.crates.io-6f17d22bba15001f/clap/src/mkeymap.rs",
                  "/home/kali/.cargo/registry/src//inflate/src/mkeymap.rs",
                  "/deps/miniz_oxide-0.7.4/src/inflate/core.rs"]
        test_result_2 = ["miniz_oxide-0.7.4"]
        self.assertCountEqual(get_crates(test_2), test_result_2)
        print("[test] get_crates_test_2 success!")

        test_3 = ["src/.cargo/registry/src/gitlab.local-6e6d3f8bd0b6968f/tokio-1.34.0/src/runtime/context/runtime.rs"]
        test_result_3 = ["tokio-1.34.0"]
        self.assertCountEqual(get_crates(test_3), test_result_3)
        print("[test] get_crates_test_3 success!")

        test_4 = ["C:\\Users\\user\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\rand-0.9.0-alpha.2\\src\\rngs\\thread.rs"]
        test_result_4 = ["rand-0.9.0-alpha.2"]
        self.assertCountEqual(get_crates(test_4), test_result_4)
        print("[test] get_crates_test_4 success!")

    def test_get_commithash(self):
        test_1 = [r"/rustc/07dca489ac2d933c78d3c5158e3f43beefeb02ce\library\core\src"]
        test_result_1 = "07dca489ac2d933c78d3c5158e3f43beefeb02ce"
        self.assertEqual(get_commithash(test_1), test_result_1)
        print("[test] get_commithash_test_1 success!")

        test_2 = [r"/rustc/7dca489ac2d933c78d3c5158e3f43beefeb02ce\library\core\src"]
        test_result_2 = None
        self.assertEqual(get_commithash(test_2), test_result_2)
        print("[test] get_commithash_test_2 success!")


if __name__ == '__main__':
    unittest.main()
