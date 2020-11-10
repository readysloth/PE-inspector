import struct
import typing as t

def slice_to_format_size(format: str, _bytes: bytes) -> bytes:
    return _bytes[:struct.calcsize(format)]


def merge_format(format: t.List[t.Dict[str, str]]) -> t.Dict[str, str]:
    merged_format = {}
    for d in format:
        merged_format = {**merged_format, **d}
    return merged_format


def compact_format(format: t.List[t.Dict[str, str]]) -> str:
    return ''.join([v for k,v in merge_format(format).items()])


def get_format_names(format: t.List[t.Dict[str, str]]) -> t.List[str]:
    return [list(d.keys())[0] for d in format]


class FileFormat:
    def __init__(self, format: t.List[t.Dict[str, str]],  _bytes: bytes):
        self.format = format
        format_names = get_format_names(format)
        compacted_format = compact_format(format)
        for i, item in enumerate(struct.unpack_from(compacted_format, _bytes)):
            setattr(self, format_names[i], item)

    def __str__(self) -> str:
        return '\n'.join([f'{fn}: {str(getattr(self, fn))}' for fn in get_format_names(self.format)])


class MZ(FileFormat):
    FORMAT = [{'signature'          :  '2s'},
              {'extra_bytes'        :  'H'},
              {'pages'              :  'H'},
              {'relocation_items'   :  'H'},
              {'header_size'        :  'H'},
              {'minimum_allocation' :  'H'},
              {'maximum_allocation' :  'H'},
              {'initial_ss'         :  'H'},
              {'initial_sp'         :  'H'},
              {'checksum'           :  'H'},
              {'initial_ip'         :  'H'},
              {'initial_cs'         :  'H'},
              {'relocation_table'   :  'H'},
              {'overlay'            :  'H'}]

    def __init__(self, _bytes: bytes):
        super().__init__(MZ.FORMAT, _bytes)
