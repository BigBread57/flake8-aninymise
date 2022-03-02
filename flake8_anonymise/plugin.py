import ast
from _ast import (
    arguments,
    Assign,
    Attribute,
    Call,
    ClassDef,
    Expr,
    FunctionDef,
    List,
    Name,
)
from pprint import pprint
from typing import Any, Generator, Tuple, Type


class AdbVision(ast.NodeVisitor):
    """Проверка файла на наличие класса, удовлетворяющего условиям."""

    def __init__(self, *args, **kwargs) -> None:
        """Установка праметров и переменных для хранения данных."""
        self.type_field = [
            'AutoField', 'BigAutoField', 'BigIntegerField', 'BinaryField',
            'BooleanField', 'CharField', 'DateField', 'DateTimeField',
            'DecimalField', 'DurationField', 'EmailField', 'FileField',
            'FieldFile', 'FilePathField', 'FloatField', 'ImageField',
            'IntegerField', 'GenericIPAddressField', 'JSONField',
            'PositiveBigIntegerField', 'PositiveIntegerField',
            'PositiveSmallIntegerField', 'SlugField', 'SmallAutoField',
            'SmallIntegerField', 'TextField', 'TimeField', 'URLField',
            'UUIDField', 'ForeignKey', 'ManyToManyField', 'OneToOneField',
        ]
        # список выявленных ошибок
        self.problems: List[Tuple[int, int, str]] = []
        # название родительского класса от которого наследуются модели
        self.parent_class = ['models.Model']
        # название внутреннего класса необходимого для анонимизации
        self.param_part_name_class_anonymise = 'PrivacyMeta'
        # поля обязательные во внутреннем классе
        self.param_fields_sub_class = ['fields', 'non_sensitive']
        # функция регистрации модели и класса для анонимизации
        self.param_func_anonymise = 'gdpr_assist.register'
        # часть названия функции для анонимизации
        self.param_part_name_function = 'anonymise'

        self.fields_django_model = []  # аттрибуты модели
        # аттрибуты внутри PrivacyMeta ('fields', 'non_sensitive')
        self.fields_sub_class = {}
        self.name_function_sub_class = []  # имена функций внутри PrivacyMeta

        self.main_class = ''  # название модели
        self.anonymise_class = ''  # название класса анонимизации

        # указатель на то, что анализируем тело класса модели
        self.is_django_model = False
        # указатель на то, что анализируем тело класса PrivacyMeta
        self.is_anonymise_class = False
        # указатель на то, что ищем функцию регистрации, вне класса модели
        self.is_search_gdpr = False

        self.errors = {
            'ADB1': 'ADB1 В моделе {main_class} отсутсвует класс ' +
                    'PrivacyMeta, его необходимо создать.',
            'ADB2': 'ADB2 В классе PrivacyMeta модели не {main_class} ' +
                    'отображены поля {value_fields}. Все поля из модели ' +
                    '{main_class} необходимо отразить в PrivacyMeta ' +
                    'в установленных переменных.',
            'ADB3': 'ADB3 В классе PrivacyMeta, отсуствует ' +
                    'переменная {field}',
            'ADB4': 'ADB4 Отсуствует регистрация модели {main_class} через ' +
                    '{gdpr_register}',
            'ADB5': 'ADB5 Для переменной {variable} внутри fields не ' +
                    'установлена функция анонимизации anonymise_{variable}',
            'ADB6': 'ADB6 Регистрация модели указана неверно. Необходимо ' +
                    'gdpr_assist.register({main_class}, ' +
                    '{main_class}.PrivacyMeta), а указно ' +
                    '{gdpr_register}({main_class}, {secondary_class})',
        }

    @staticmethod
    def convert_list(params_list: list) -> list:
        """Преобразование переданных параметров в единый список.

        Пример:
        Получаем - param_parent_class_with_packet = ['models.Model'].
        Получаем - parent_class = ['models.Model'].
        Отдаем - result = ['models', 'Model'].
        """
        result = []

        for elem in params_list:
            if elem.find('.'):
                result.extend(elem.split('.'))
            else:
                result.extend(elem)

        return result

    @staticmethod
    def difference_set(first_set: list, second_set: list) -> list:
        """Возвращает список полей, которые не отражены в PrivacyMeta."""
        return list(set(first_set).difference(set(second_set)))

    @property
    def list_classes_for_gdpr_register(self):
        """Формирует список из элементов внутри функции gdpr.register."""
        secondary_class_with_parent_class = '{0}.{1}'.format(
            self.main_class, self.anonymise_class,
        )
        return [self.main_class, secondary_class_with_parent_class]

    @staticmethod
    def issubset_set(first_list: list, second_list: list) -> bool:
        """Проверяет корректность регистрации классов в gdpr.register."""
        return set(first_list).issubset(set(second_list))

    def distribution_error(self, error: str, **kwargs):
        """Работа с найденными ошибками."""

        text_error = self.errors.get(error)
        if error == 'ADB1':
            text_error = text_error.format(
                main_class=kwargs['main_class'],
            )
        elif error == 'ADB2':
            text_error = text_error.format(
                main_class=self.main_class,
                value_fields=kwargs['missing_value_fields'],
            )
        elif error == 'ADB3':
            text_error = text_error.format(
                main_class=self.main_class,
                field=kwargs['field'],
            )
        elif error == 'ADB4':
            text_error = text_error.format(
                main_class=self.main_class,
                gdpr_register=self.param_func_anonymise
            )
        elif error == 'ADB5':
            text_error = text_error.format(
                variable=kwargs['variable'],
            )
        elif error == 'ADB6':
            text_error = text_error.format(
                gdpr_register=self.param_func_anonymise,
                main_class=self.main_class,
                secondary_class=self.anonymise_class,
            )

        self.problems.append((kwargs['line'], kwargs['col'], text_error))

    def analysis_body(self, node):
        """Анализ тела класса."""
        for part_body in node.body:

            if isinstance(part_body, ClassDef):
                # ищем класс PrivacyMeta в нашей модели
                if part_body.name == self.param_part_name_class_anonymise:
                    if not self.anonymise_class:
                        self.anonymise_class = part_body.name
                        self.is_anonymise_class = True
                        self.visit_ClassDef(part_body)
                        self.is_anonymise_class = False

            # осуществляем поиск полей модели или переменных
            if isinstance(part_body, Assign):
                self.visit_Assign(part_body)

            # осуществляем поиск функций внутри PrivacyMeta
            if isinstance(part_body, FunctionDef) and self.is_anonymise_class:
                self.visit_FunctionDef(part_body)

        # Если внутри модели нет класса PrivacyMeta
        if not self.anonymise_class:
            self.distribution_error(
                error='ADB1',
                line=node.lineno,
                col=node.col_offset,
                main_class=self.main_class,
            )

        self.is_django_model = False
        self.analysis_gdpr(node)

    def analysis_gdpr(self, node):
        """После анализа тела модели, ищем gdpr_assist.registry()."""
        if node.name == self.main_class:
            self.visit_Expr(node)

            # все поля модели, сейчас запакованы в словарь вида:
            # {fields:[], non_sensitive:[]}. Необходимо распокавть.
            all_value_fields = []
            for key, list_value in self.fields_sub_class.items():

                # отсутсвует переменная 'fields' или 'non_sensitive'
                if key not in self.param_fields_sub_class:
                    self.distribution_error(
                        error='ADB3',
                        line=node.lineno,
                        col=node.col_offset,
                        field=key,
                    )
                if key == 'fields':
                    for value in list_value:
                        name_func = '{}_{}'.format('anonymise', value)

                        # отсутствует функция анонимизации для поля модели
                        if name_func not in self.name_function_sub_class:
                            self.distribution_error(
                                error='ADB5',
                                line=node.lineno,
                                col=node.col_offset,
                                variable=value,
                            )

                all_value_fields.extend(list_value)

            # проверка, что все поля модели определы в переменных
            # 'fields' или 'non_sensitive'
            missing_value_fields = self.difference_set(
                self.fields_django_model,
                all_value_fields,
            )
            if missing_value_fields:
                self.distribution_error(
                    error='ADB2',
                    line=node.lineno,
                    col=node.col_offset,
                    missing_value_fields=missing_value_fields,
                )

    def visit_ClassDef(self, node):
        """Поиск необходимых классов."""
        if hasattr(node, 'bases'):  # ищем классы, у которых есть родитель

            self.is_django_model = True
            is_model_attr = False
            is_model_name = False
            for base in node.bases:  # проверяем от чего наследуется класс
                if isinstance(base, Attribute):
                    is_model_attr = self.visit_Attribute(base)
                if isinstance(base, Name):
                    is_model_name = self.visit_Name(base)

            # Анализируем тело родительского класса
            if is_model_attr or is_model_name:
                self.main_class = node.name
                self.analysis_body(node)

        # анализируем класс PrivacyMeta
        if node.name == self.anonymise_class:
            self.analysis_body(node)

        return False

    def visit_Name(self, node):
        """Проверяем узлы, которые имеют класс Name."""
        if self.is_django_model:

            # проверка при поиске родительского класса и полей модели
            if node.id in self.convert_list(self.parent_class):
                return node.id

            # проверка при поиске атрибутов PrivacyMeta
            if node.id in self.param_fields_sub_class:
                return node.id

        if self.is_search_gdpr:

            # проверка при поиске функции gdpr_assist.register
            if node.id in self.param_func_anonymise.split('.'):
                return node.id

            # проверка при поиске аргументов функции gdpr_assist.register
            if node.id == self.main_class:
                return node.id

        ast.NodeVisitor.generic_visit(self, node)
        return False

    def visit_Attribute(self, node):
        """Проверяем узлы, которые имеют класс Attribute."""
        if isinstance(node.value, Name):
            name = self.visit_Name(node.value)

            if self.is_django_model:

                # ищем сопадения с models.Model или типами полей
                if node.attr in [*self.convert_list(self.parent_class), *self.type_field]:
                    return '{}.{}'.format(name, node.attr)

            if self.is_search_gdpr:

                if node.attr in self.param_func_anonymise.split('.'):
                    return '{}.{}'.format(name, node.attr)

                if node.attr == self.anonymise_class:
                    return '{}.{}'.format(name, node.attr)

        ast.NodeVisitor.generic_visit(self, node)
        return False

    def visit_Assign(self, node):
        """Проверяем узлы, которые имеют класс Assign."""
        if self.is_django_model:

            # Проверка для выявления полей модели
            if isinstance(node.value, Call):
                assign_value = self.visit_Call(node.value)

                # Если условия на соотвествие полям модели пройдены,
                # то заносим данное поле в хранилище
                if assign_value:
                    if isinstance(node.targets[0], Name):
                        self.fields_django_model.append(node.targets[0].id)

            # Проверка для выявления атрибутов класса PrivacyMeta
            elif isinstance(node.value, List):

                if isinstance(node.targets[0], Name):
                    name = self.visit_Name(node.targets[0])

                    # Получаем из атрибутов все значения (то есть список полей
                    # из fields и non_sensitive) и формируем словарь
                    if name in self.param_fields_sub_class:
                        result_visit = self.visit_List(node.value)
                        self.fields_sub_class.update({str(name): result_visit})

        ast.NodeVisitor.generic_visit(self, node)
        return False

    def visit_List(self, node):
        """Проверяем узлы, которые имеют класс List."""
        if self.is_django_model:
            list_of_field_values = []
            # получаем все значения из списков fields non_sensitive
            for elt in node.elts:
                list_of_field_values.append(self.visit_Constant(elt))
            return list_of_field_values

        ast.NodeVisitor.generic_visit(self, node)
        return False

    def visit_Constant(self, node):
        """Проверяем узлы, которые имеют класс Constant."""
        if self.is_django_model:
            return node.value

        ast.NodeVisitor.generic_visit(self, node)
        return False

    def visit_FunctionDef(self, node):
        """Проверяем узлы, которые имеют класс FunctionDef."""
        if self.is_django_model:
            if node.name.find(self.param_part_name_function) >= 0:
                self.name_function_sub_class.append(node.name)
                return node.name

        ast.NodeVisitor.generic_visit(self, node)
        return False

    def visit_Call(self, node):
        """Проверяем узлы, которые имеют класс Call."""
        if self.is_django_model:
            # проверка для выяления полей модели
            if isinstance(node.func, Attribute):
                return self.visit_Attribute(node.func)

        if self.is_search_gdpr and hasattr(node, 'func'):
            if isinstance(node.func, Attribute):
                result_visit = self.visit_Attribute(node.func)
                if result_visit:
                    result_visit = self.visit_arguments(node)
                    self.is_search_gdpr = False
                    if not self.issubset_set(
                        result_visit,
                        self.list_classes_for_gdpr_register,
                    ):
                        self.distribution_error(
                            'ADB6',
                            line=node.lineno,
                            col=node.col_offset,
                        )
                else:
                    self.distribution_error(
                        'ADB4',
                        line=node.lineno,
                        col=node.col_offset,
                    )
                    self.is_search_gdpr = False

        ast.NodeVisitor.generic_visit(self, node)
        return False

    def visit_Expr(self, node):
        """Проверяем узлы, которые имеют класс Expr."""
        if not self.is_django_model and self.main_class:
            if isinstance(node, Expr):
                if isinstance(node.value, Call):
                    self.is_search_gdpr = True
                    self.visit_Call(node.value)
            else:
                ast.NodeVisitor.generic_visit(self, node)
        return False

    def visit_arguments(self, node: arguments) -> list:
        """Проверяем узлы, которые имеют класс args."""
        if self.is_search_gdpr:
            list_param = []
            for arg in node.args:

                if isinstance(arg, Name):
                    list_param.append(self.visit_Name(arg))
                elif isinstance(arg, Attribute):
                    list_param.append(self.visit_Attribute(arg))

            if list_param:
                return list_param

        ast.NodeVisitor.generic_visit(self, node)
        return []


class AdbExtension(object):
    """Плагин для проверки корректности анонимизации базы данных."""

    name = 'flake8-anonymise'
    version = '0.0.1'

    def __init__(self, tree: ast.AST, *args) -> None:
        """Получаем древовидное представление исходного кода."""
        self.tree = tree

    def run(self) -> Generator[Tuple[int, int, str, Type[Any]], None, None]:
        """Выводим найденные ошибки, исходя из логики плагина."""
        parser = AdbVision()
        parser.visit(self.tree)
        for line, col, problem in sorted(parser.problems):
            yield line, col, problem, type(self)
