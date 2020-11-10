import struct
import typing as t

from datetime import datetime

class Field:
    def __init__(self,
                 name: str,
                 format: str,
                 desc: str = '',
                 value: t.Any = None,
                 value_fmt: t.Callable = None):
        self.name = name
        self.format = format
        self.desc = desc
        self.value = value
        self.value_fmt = value_fmt

    def __str__(self) -> str:
        value = str(self.value)[:14] if not self.value_fmt else self.value_fmt(self.value)
        return f'{self.name: <30} : {value : <30} : {struct.calcsize(self.format): ^4} : {self.desc}'


def slice_to_format_size(format: str, _bytes: bytes) -> bytes:
    return _bytes[:struct.calcsize(format)]


def compact_format(format: t.List[Field]) -> str:
    return ''.join([f.format for f in format])


def get_format_names(format: t.List[Field]) -> t.List[str]:
    return [f.name for f in format]


class FileFormat:
    def __init__(self, format: t.List[Field],  _bytes: bytes):
        self.structure = format
        self._format_names = get_format_names(format)
        self._compacted_format = compact_format(format)
        for field, value in zip(self.structure,
                                struct.unpack_from(self._compacted_format, _bytes)):
            field.value = value
            setattr(self, field.name, value)

    def __str__(self) -> str:
        return f'{"Name": ^30} : {"Value": ^30} : {"Size": ^4} : Description\n' \
             + '-'*(30+16+4+3*3+len('Description')) \
             + '\n' \
             + '\n'.join([str(f) for f in self.structure])

    def __len__(self) -> int:
        return struct.calcsize(self._compacted_format)


class MZ(FileFormat):

    FORMAT = [Field('e_magic'   , '2s', 'Magic number'                     ),
              Field('e_cblp'    ,  'H', 'Bytes on last page of file'       ),
              Field('e_cp'      ,  'H', 'Pages in file'                    ),
              Field('e_crlc'    ,  'H', 'Relocations'                      ),
              Field('e_cparhdr' ,  'H', 'Size of header in paragraphs'     ),
              Field('e_minalloc',  'H', 'Minimum extra paragraphs needed'  ),
              Field('e_maxalloc',  'H', 'Maximum extra paragraphs needed'  ),
              Field('e_ss'      ,  'H', 'Initial (relative) SS value'      ),
              Field('e_sp'      ,  'H', 'Initial SP value'                 ),
              Field('e_csum'    ,  'H', 'Checksum'                         ),
              Field('e_ip'      ,  'H', 'Initial IP value'                 ),
              Field('e_cs'      ,  'H', 'Initial (relative) CS value'      ),
              Field('e_lfarlc'  ,  'H', 'File address of relocation table' ),
              Field('e_ovno'    ,  'H', 'Overlay number'                   ),
              Field('e_res1'    , '8s', 'Reserved words'                   ),
              Field('e_oemid'   ,  'H', 'OEM identifier (for e_oeminfo)'   ),
              Field('e_oeminfo' ,  'H', 'OEM information; e_oemid specific'),
              Field('e_res2'    ,'20s', 'Reserved words'                   ),
              Field('e_lfanew'  ,  'i', 'File address of new exe header'   )]

    def __init__(self, _bytes: bytes):
        super().__init__(MZ.FORMAT, _bytes)


class PE(FileFormat):

    FORMAT = [Field('mMagic'                , '4s' , 'PE\0\0 or 0x00004550'),
              Field('mMachine'              , 'H'),
              Field('mNumberOfSections'     , 'H'),
              Field('mTimeDateStamp'        , '4s',
                    value_fmt=lambda v: datetime.utcfromtimestamp(int.from_bytes(v, 'little')).strftime('%H:%M:%S %d-%m-%Y')),
              Field('mPointerToSymbolTable' , '4s'),
              Field('mSizeOfOptionalHeader' , 'H'),
              Field('mCharacteristics'      , 'H'),
              ]

    def __init__(self, _bytes: bytes):
        self.mz = MZ(_bytes)
        super().__init__(PE.FORMAT, _bytes[self.mz.e_lfanew:])
