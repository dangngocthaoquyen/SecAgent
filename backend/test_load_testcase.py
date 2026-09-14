from pathlib import Path

from src.testing.testcase_loader import TestCaseLoader


loader = TestCaseLoader()

def test_load_testcase() -> None:
    testcase = loader.load(
        Path(__file__).resolve().parent.parent
        / "testcases"
        / "prompt_injection"
        / "PI-001.yaml"
    )

    assert testcase.id == "PI-001"
    assert testcase.taxonomy.mitre_atlas

    print("ID:")
    print(testcase.id)

    print("\nNAME:")
    print(testcase.name)

    print("\nCATEGORY:")
    print(testcase.category)

    print("\nATTACK TYPE:")
    print(testcase.attack_type)

    print("\nOWASP:")
    print(testcase.taxonomy.owasp)

    print("\nMITRE ATLAS:")
    print(testcase.taxonomy.mitre_atlas)

    print("\nPAYLOAD REFS:")
    print(testcase.payload_refs)

    print("\nEVALUATION:")
    print(testcase.evaluation)


if __name__ == "__main__":
    test_load_testcase()