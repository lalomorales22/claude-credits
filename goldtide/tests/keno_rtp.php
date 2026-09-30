<?php
/**
 * Kelp Keno paytable solver / checker. Run: php goldtide/tests/keno_rtp.php   (exit 0 = every pick count inside 94–96%)
 *
 * 40 balls, 10 drawn, pick p: P(catch k) = C(p,k)·C(40-p,10-k) / C(40,10) (hypergeometric), RTP(p) = Σ_k P(k)·pay[p][k].
 * The "solver" is a greedy nudge: starting from the shipped KENO_PAY, for every pick count outside the band it prints the
 * sensitivity of each cell (RTP change per +0.1×) so the smallest edit that lands the row inside 94–96% is obvious; the
 * shipped table is the result of applying exactly those edits (pick 3 catch-2 3.5→3.6, pick 6 catch-4 8→9, pick 8 catch-5
 * 14→15, pick 10 catch-5 5.5→5.2). Payouts are pay_mult(bet, m) (nearest coin); every multiplier ×10 is an integer, so
 * the RTP is identical at every bet from 10 to 5,000 GC.
 */
declare(strict_types=1);
define('GT_NO_ROUTE', 1);
require dirname(__DIR__) . '/index.php';

function choose(int $n, int $k): float { if ($k < 0 || $k > $n) { return 0.0; } $r = 1.0; for ($i = 1; $i <= $k; $i++) { $r = $r * ($n - $k + $i) / $i; } return $r; }
function keno_prob(int $p, int $k): float { return choose($p, $k) * choose(40 - $p, 10 - $k) / choose(40, 10); }
function keno_rtp(int $p, array $pay): float { $r = 0.0; foreach ($pay as $k => $m) { $r += keno_prob($p, $k) * $m; } return $r; }

$bad = 0;
foreach (KENO_PAY as $p => $pay) {
    $rtp = keno_rtp($p, $pay) * 100;
    $in = $rtp >= 94 && $rtp <= 96; if (!$in) { $bad++; }
    printf("pick %2d: RTP %6.2f%% %s   pays [%s]\n", $p, $rtp, $in ? 'ok ' : 'OUT', implode(', ', $pay));
    if (!$in || in_array('-v', $GLOBALS['argv'], true)) {
        foreach ($pay as $k => $m) { if ($k > 0) { printf("          catch %2d: P=%.6f  +0.1× → %+.3f pp\n", $k, keno_prob($p, $k), keno_prob($p, $k) * 10); } }
    }
}
echo $bad ? "$bad pick count(s) outside 94–96%\n" : "all 10 pick counts inside 94–96%\n";
exit($bad ? 1 : 0);
