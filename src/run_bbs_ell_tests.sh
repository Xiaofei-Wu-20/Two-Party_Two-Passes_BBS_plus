#!/bin/bash
# ==============================
# 自动批量测试不同消息长度 ell
# ==============================

cd "$(dirname "$0")"   # 确保脚本从 src/ 运行

OUT_DIR="../build"
RESULT_FILE="$OUT_DIR/results.csv"


mkdir -p "$OUT_DIR"
echo "ell,KeyGen_mean_ms,P1_total_ms,P2_ms" > "$RESULT_FILE"

for ell in 1 50 100 150 200 250 300 350 400 450 500;

do
    echo -e "\n=== Building for BBS_ELL=$ell ==="

    g++ -std=c++17 -O2 -DBBS_ELL=$ell \
    main.cpp \
    Party1.cpp \
    Party2.cpp \
    zk_sigma.cpp \
    ecvrf_p256.c \
    -I../include \
    -I../include/mcl/include \
    -I../include/bicycl \
    -L../include/mcl/build/lib -lmcl \
    -lssl -lcrypto -lgmp -lgmpxx \
    -o "$OUT_DIR/test_bbs_ell_$ell"


    if [ $? -ne 0 ]; then
        echo "[Error] ❌ Compile failed for ell=$ell"
        exit 1
    fi

    echo "=== Running test (ell=$ell) ==="
    LD_LIBRARY_PATH=../include/mcl/build/lib "$OUT_DIR/test_bbs_ell_$ell" > "$OUT_DIR/output_$ell.txt"

    keygen_mean=$(grep "KeyGen" "$OUT_DIR/output_$ell.txt" | awk '{print $2}')
    p1_mean=$(grep "Avg P1" "$OUT_DIR/output_$ell.txt" | awk '{print $3}')
    p2_mean=$(grep "Avg P2" "$OUT_DIR/output_$ell.txt" | awk '{print $3}')

    if [ -z "$keygen_mean" ] || [ -z "$p1_mean" ] || [ -z "$p2_mean" ]; then
        echo "[Warning] ⚠️ Parsing failed for ell=$ell"
    else
        echo "$ell,$keygen_mean,$p1_mean,$p2_mean" >> "$RESULT_FILE"
        echo "[OK] ✅ ell=$ell  KeyGen=$keygen_mean  P1=$p1_mean  P2=$p2_mean"
    fi
done

echo -e "\n✅ All tests completed. Results saved to $RESULT_FILE"
