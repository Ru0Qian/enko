"""Tests for DEX2C translator helpers: type descriptors, JNI signatures."""

import pytest

import sys
from pathlib import Path

_packer = Path(__file__).resolve().parent.parent / "packer"
if str(_packer) not in sys.path:
    sys.path.insert(0, str(_packer))

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "packer" / "dex2c"))

from translator import (
    _desc_to_jni_type,
    _desc_is_wide,
    _desc_is_void,
    _desc_is_ref,
    _iter_param_descs,
    _return_desc,
    _jni_call_variant,
    _jni_field_variant,
    _reg_field,
    _desc_to_jni_slash,
)


class TestDescToJniType:
    def test_void(self):
        assert _desc_to_jni_type("V") == "void"

    def test_boolean(self):
        assert _desc_to_jni_type("Z") == "jboolean"

    def test_byte(self):
        assert _desc_to_jni_type("B") == "jbyte"

    def test_char(self):
        assert _desc_to_jni_type("C") == "jchar"

    def test_short(self):
        assert _desc_to_jni_type("S") == "jshort"

    def test_int(self):
        assert _desc_to_jni_type("I") == "jint"

    def test_long(self):
        assert _desc_to_jni_type("J") == "jlong"

    def test_float(self):
        assert _desc_to_jni_type("F") == "jfloat"

    def test_double(self):
        assert _desc_to_jni_type("D") == "jdouble"

    def test_object_reference(self):
        assert _desc_to_jni_type("Ljava/lang/String;") == "jobject"

    def test_array(self):
        assert _desc_to_jni_type("[I") == "jobject"

    def test_empty_string(self):
        assert _desc_to_jni_type("") == "jobject"

    def test_unknown_returns_jobject(self):
        assert _desc_to_jni_type("X") == "jobject"


class TestDescIsWide:
    def test_long_is_wide(self):
        assert _desc_is_wide("J") is True

    def test_double_is_wide(self):
        assert _desc_is_wide("D") is True

    def test_int_is_not_wide(self):
        assert _desc_is_wide("I") is False

    def test_object_is_not_wide(self):
        assert _desc_is_wide("Ljava/lang/String;") is False

    def test_empty_is_not_wide(self):
        assert not _desc_is_wide("")


class TestDescIsVoid:
    def test_void(self):
        assert _desc_is_void("V") is True

    def test_not_void(self):
        for t in "ZBCSIJFD":
            assert _desc_is_void(t) is False

    def test_object_not_void(self):
        assert _desc_is_void("Ljava/lang/Object;") is False


class TestDescIsRef:
    def test_class_ref(self):
        assert _desc_is_ref("Lcom/example/Foo;") is True

    def test_array_ref(self):
        assert _desc_is_ref("[I") is True

    def test_primitive_not_ref(self):
        for t in "ZBCSIJFDV":
            assert _desc_is_ref(t) is False

    def test_empty_not_ref(self):
        assert not _desc_is_ref("")


class TestIterParamDescs:
    def test_no_params(self):
        descs = list(_iter_param_descs("()V"))
        assert descs == []

    def test_single_int(self):
        descs = list(_iter_param_descs("(I)V"))
        assert descs == ["I"]

    def test_multiple_primitives(self):
        descs = list(_iter_param_descs("(IJF)V"))
        assert descs == ["I", "J", "F"]

    def test_mixed_primitives_and_objects(self):
        descs = list(_iter_param_descs("(ILjava/lang/String;Z)V"))
        assert descs == ["I", "Ljava/lang/String;", "Z"]

    def test_array_params(self):
        descs = list(_iter_param_descs("([I[[Ljava/lang/Object;)V"))
        assert descs == ["[I", "[[Ljava/lang/Object;"]

    def test_complex_signature(self):
        descs = list(_iter_param_descs("(IJLjava/lang/String;[BZD)V"))
        assert descs == ["I", "J", "Ljava/lang/String;", "[B", "Z", "D"]

    def test_invalid_input_returns_nothing(self):
        # No opening paren
        descs = list(_iter_param_descs("IV"))
        assert descs == []

    def test_empty_string(self):
        descs = list(_iter_param_descs(""))
        assert descs == []


class TestReturnDesc:
    def test_void(self):
        assert _return_desc("()V") == "V"

    def test_int(self):
        assert _return_desc("()I") == "I"

    def test_object(self):
        assert _return_desc("()Ljava/lang/String;") == "Ljava/lang/String;"

    def test_with_params(self):
        assert _return_desc("(IJLjava/lang/String;)D") == "D"


class TestJniCallVariant:
    def test_void(self):
        assert _jni_call_variant("V") == "Void"

    def test_int(self):
        assert _jni_call_variant("I") == "Int"

    def test_long(self):
        assert _jni_call_variant("J") == "Long"

    def test_object(self):
        assert _jni_call_variant("Ljava/lang/String;") == "Object"

    def test_array(self):
        assert _jni_call_variant("[I") == "Object"

    def test_empty_returns_object(self):
        assert _jni_call_variant("") == "Object"

    def test_all_primitives(self):
        expected = {
            "V": "Void", "Z": "Boolean", "B": "Byte", "C": "Char",
            "S": "Short", "I": "Int", "J": "Long", "F": "Float", "D": "Double",
        }
        for desc, suffix in expected.items():
            assert _jni_call_variant(desc) == suffix


class TestJniFieldVariant:
    def test_int(self):
        assert _jni_field_variant("I") == "Int"

    def test_boolean(self):
        assert _jni_field_variant("Z") == "Boolean"

    def test_object(self):
        assert _jni_field_variant("Ljava/lang/String;") == "Object"

    def test_empty_returns_object(self):
        assert _jni_field_variant("") == "Object"


class TestRegField:
    def test_int_reg(self):
        assert _reg_field("I") == "i"

    def test_long_reg(self):
        assert _reg_field("J") == "j"

    def test_float_reg(self):
        assert _reg_field("F") == "f"

    def test_double_reg(self):
        assert _reg_field("D") == "d"

    def test_object_reg(self):
        assert _reg_field("Ljava/lang/String;") == "l"

    def test_array_reg(self):
        assert _reg_field("[I") == "l"

    def test_empty_defaults_to_i(self):
        assert _reg_field("") == "i"

    def test_void_defaults_to_i(self):
        assert _reg_field("V") == "i"


class TestDescToJniSlash:
    def test_class_descriptor(self):
        assert _desc_to_jni_slash("Lcom/example/Foo;") == "com/example/Foo"

    def test_primitive_passthrough(self):
        assert _desc_to_jni_slash("I") == "I"
        assert _desc_to_jni_slash("V") == "V"

    def test_array_passthrough(self):
        assert _desc_to_jni_slash("[I") == "[I"
