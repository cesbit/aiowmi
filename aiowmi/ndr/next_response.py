from abc import ABC, abstractmethod
from typing import OrderedDict
from .object_block import ObjectBlock
from .class_part import ClassPart
from .property_info import PropertyInfo


class NextResponse(ABC):

    def get_properties(
            self,
            ignore_defaults: bool = False,
            ignore_missing: bool = False,
            load_qualifiers: bool = False) -> OrderedDict[str, PropertyInfo]:
        """Get properties
        ignore_defaults: Ignore default values. Set missing values to None
                         if a value does not exist in the current class.
                         ignore_defaults will always be True if ignore_missing
                         is set to True.
        ignore_missing: If set to True, values missing in the current class
                        will not be part of the result.
        load_qualifiers: Load the qualifiers of the properties. If not, the
                         property qualifier_set will have the offset in the
                        heap where the qualifiers are stored.
        """

        items = []
        object_block = self._get_object_block()
        class_part = object_block.class_part
        properties = class_part.properties

        if ignore_missing:
            # we need a copy when missing values must be ignored
            properties = properties.copy()

        if not ignore_defaults:
            properties.set_prop_defaults(class_part.nd_value_table)
            properties.set_prop_values(
                class_part.class_heap,
                class_part.nd_value_table,
                set_defaults=True)

        properties.set_prop_values(
            object_block.instance_heap,
            object_block.nd_value_table,
            ignore_missing=ignore_missing,
            ignore_defaults=ignore_defaults)

        if load_qualifiers:
            properties.set_qualifiers(class_part.class_heap)

        # clear the class part from the object block
        self._obj_block.class_part = None

        return properties.properties

    @abstractmethod
    def _get_object_block(self) -> ObjectBlock:
        ...

    def get_class_part(self) -> ClassPart:
        return self._get_object_block().class_part
