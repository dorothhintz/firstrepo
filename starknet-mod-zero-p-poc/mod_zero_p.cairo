%builtins output pedersen range_check ecdsa bitwise ec_op keccak poseidon range_check96 add_mod mul_mod

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import ModBuiltin, UInt384
from starkware.cairo.common.registers import get_label_location

// 16 real add_mod instances, all with n=1, but with the invalid modulus p=0.
// Values are chosen so a+b=c as ordinary integers (3+4=7), allowing us to test
// whether the STWO AIR accepts the degenerate p=0 case while Cairo VM secure checks reject it.
func main{
    output_ptr,
    pedersen_ptr,
    range_check_ptr,
    ecdsa_ptr,
    bitwise_ptr,
    ec_op_ptr,
    keccak_ptr,
    poseidon_ptr,
    range_check96_ptr,
    add_mod_ptr : ModBuiltin*,
    mul_mod_ptr,
}() {
    alloc_locals;

    let p = UInt384(d0=0, d1=0, d2=0, d3=0);
    let (values_ptr: UInt384*) = alloc();
    assert values_ptr[0] = UInt384(d0=3, d1=0, d2=0, d3=0);
    assert values_ptr[1] = UInt384(d0=4, d1=0, d2=0, d3=0);
    assert values_ptr[2] = UInt384(d0=7, d1=0, d2=0, d3=0);

    let (offsets_ptr) = get_label_location(add_offsets);

    assert add_mod_ptr[0] = ModBuiltin(p=p, values_ptr=values_ptr, offsets_ptr=offsets_ptr, n=1);
    assert add_mod_ptr[1] = ModBuiltin(p=p, values_ptr=values_ptr, offsets_ptr=offsets_ptr, n=1);
    assert add_mod_ptr[2] = ModBuiltin(p=p, values_ptr=values_ptr, offsets_ptr=offsets_ptr, n=1);
    assert add_mod_ptr[3] = ModBuiltin(p=p, values_ptr=values_ptr, offsets_ptr=offsets_ptr, n=1);
    assert add_mod_ptr[4] = ModBuiltin(p=p, values_ptr=values_ptr, offsets_ptr=offsets_ptr, n=1);
    assert add_mod_ptr[5] = ModBuiltin(p=p, values_ptr=values_ptr, offsets_ptr=offsets_ptr, n=1);
    assert add_mod_ptr[6] = ModBuiltin(p=p, values_ptr=values_ptr, offsets_ptr=offsets_ptr, n=1);
    assert add_mod_ptr[7] = ModBuiltin(p=p, values_ptr=values_ptr, offsets_ptr=offsets_ptr, n=1);
    assert add_mod_ptr[8] = ModBuiltin(p=p, values_ptr=values_ptr, offsets_ptr=offsets_ptr, n=1);
    assert add_mod_ptr[9] = ModBuiltin(p=p, values_ptr=values_ptr, offsets_ptr=offsets_ptr, n=1);
    assert add_mod_ptr[10] = ModBuiltin(p=p, values_ptr=values_ptr, offsets_ptr=offsets_ptr, n=1);
    assert add_mod_ptr[11] = ModBuiltin(p=p, values_ptr=values_ptr, offsets_ptr=offsets_ptr, n=1);
    assert add_mod_ptr[12] = ModBuiltin(p=p, values_ptr=values_ptr, offsets_ptr=offsets_ptr, n=1);
    assert add_mod_ptr[13] = ModBuiltin(p=p, values_ptr=values_ptr, offsets_ptr=offsets_ptr, n=1);
    assert add_mod_ptr[14] = ModBuiltin(p=p, values_ptr=values_ptr, offsets_ptr=offsets_ptr, n=1);
    assert add_mod_ptr[15] = ModBuiltin(p=p, values_ptr=values_ptr, offsets_ptr=offsets_ptr, n=1);

    let add_mod_ptr = add_mod_ptr + 16 * ModBuiltin.SIZE;
    return ();

    add_offsets:
    dw 0;
    dw 4;
    dw 8;
}
