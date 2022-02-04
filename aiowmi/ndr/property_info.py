import struct
from typing import Union, Optional, List, TYPE_CHECKING
from .qualifier_set import QualifierSet
from ..cim_type import CimType
from .encoded_value import EncodedValue

if TYPE_CHECKING:
    from ..protocol import Protocol
    from ..ndr.next_response import NextResponse


class PropertyInfo:

    FMT = '<LHLL'
    FMT_SZ = struct.calcsize(FMT)

    type: int
    order: int

    def __init__(self, heap: bytes, entry: int) -> 'PropertyInfo':
        (
            self.type,
            self.order,
            value_table_offset,  # unused
            class_of_origin,  # unused
        ) = struct.unpack_from(self.FMT, heap, offset=entry)

        # see [MS-WMIO]: 2.2.32 Inherited
        # inherited = bool(self.type & CimType.CIM_INHERITED_FLAG)
        self.value = None
        self.null_default: Optional[bool] = None
        self.inherited_default: Optional[bool] = None

        # don't need the qualifiers, therefore make it optional using
        # set_qualifiers(..) and only store the offset
        self.qualifier_set: Union[QualifierSet, int] = entry + self.FMT_SZ

    def _set_qualifiers(self, heap: bytes):
        """Set qualifiers.

        The qualifiers contain info such as the CIMTYPE but they are not
        nesserary required. Therefore we do not unpack the qualifiers by
        default.
        """
        offset = self.qualifier_set
        self.qualifier_set, _ = QualifierSet.from_data(heap, offset)
        self.qualifier_set.load(heap)

    def _set_value(self, entry: int, heap: bytes):
        """Set value.

        This method can be called using different heap. From the parent class
        and from the actual class.
        """
        self.value = EncodedValue.get_value(self.type, entry, heap)

    def get_cim_type_name(self) -> str:
        """Return the name of the CIMTYPE.

        Note that in case of an array, the type of the array items will be
        returned. Thus, an array of strings would return `string`.
        """
        return CimType.get_cim_type_name(self.type)

    def is_array(self):
        """Return if this property is an array of not."""
        return self.type & CimType.CIM_ARRAY_FLAG

    def is_reference(self):
        """Return if this property is a reference."""
        p_type = self.type & ~CimType.CIM_INHERITED_FLAG
        return p_type == CimType.CIM_TYPE_REFERENCE

    def is_array_reference(self):
        """Return if this property is an array with references."""
        p_type = self.type & ~CimType.CIM_INHERITED_FLAG
        return p_type == CimType.CIM_ARRAY_REFERENCE

    def get_type(self) -> type:
        """Return the Python type for this property. Note that in case of an
        array type `list` will be returned. Use .get_cim_type() to get the
        type of items in a potential `list`.
        """
        if self.is_array():
            return list
        return CimType.get_cim_type_pytype(self.type)

    def get_cim_type(self) -> type:
        """Return the Python type for this property. In case of a `list`, the
        type for the items in the list will ne returned. For example, a list
        of strings would return type `str`. Use .get_type() if you want type
        list as a return type for a list of items.
        """
        return CimType.get_cim_type_pytype(self.type)

    async def _get_reference(
            self,
            value: str,
            service: 'Protocol',
            filter_props: Optional[List[str]] = None) -> 'NextResponse':
        from ..query import Query

        value = value[value.find(':') + 1:]

        wmiclass, value = value.split('.', 1)

        # TODO: this is not perfect as a comma could technically exist in a
        # string so we should ignore a comma inside a string.
        constraints = ' AND '.join(value.split(','))

        props = ', '.join(filter_props) if filter_props else '*'

        query = Query(f'SELECT {props} FROM {wmiclass} WHERE {constraints}')

        await query.start(service)
        res = await query.next()

        return res

    async def get_reference(
            self,
            service: 'Protocol',
            filter_props: Optional[List[str]] = None) -> 'NextResponse':
        res = await self._get_reference(self.value, service, filter_props)
        return res

    async def get_array_references(
            self,
            service: 'Protocol',
            filter_props: Optional[List[str]] = None) -> List['NextResponse']:
        arr = []
        for reference in self.value:
            res = await self._get_reference(reference, service, filter_props)
            arr.append(res)

        return arr
