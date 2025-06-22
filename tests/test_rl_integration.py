import os
import tempfile
from pathlib import Path

# Simple Python version of the logic in IA_wrapper::query_promising_keys

def query_promising_keys(best_key, top_keys, generated_file, n=3):
    result = []
    if best_key:
        result.append(best_key)
    for k in top_keys:
        if len(result) >= n:
            break
        result.append(k)
    if os.path.exists(generated_file):
        for line in open(generated_file):
            line=line.strip()
            if not line:
                continue
            result.append(line)
            if len(result) >= n:
                break
    return result[:n]

def test_query_promising_keys_integration(tmp_path):
    generated = tmp_path/'generated_keys.txt'
    generated.write_text('aaa\nbbb\n')
    res = query_promising_keys('deadbeef', ['cccc'], generated, n=3)
    assert 'deadbeef' in res
    assert 'aaa' in res
    assert len(res) == 3
