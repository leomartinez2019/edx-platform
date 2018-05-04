# -*- coding: utf-8 -*-
from __future__ import division
import csv
import json
from datetime import datetime
from collections import OrderedDict
from itertools import groupby
from operator import itemgetter


from django.conf import settings
from django.contrib.auth.models import User
from pytz import UTC

from student.models import CourseEnrollment
from lms.djangoapps.grades.new.course_grade_factory import CourseGradeFactory
from lms.djangoapps.grades.new.course_grade import CourseGrade
from lms.djangoapps.grades.new.course_data import CourseData
from openedx.core.djangoapps.content.course_structures.models import CourseStructure
from openedx.core.djangoapps.content.course_overviews.models import CourseOverview

from courseware import courses
from opaque_keys.edx.keys import CourseKey, UsageKey

from lms.djangoapps.grades.context import grading_context_for_course

from xmodule.modulestore.django import modulestore


class DictList(dict):
    """
    Modify the behavior of a dict allowing has a list of values
    when there are more than one same key.
    """
    def __setitem__(self, key, value):
        try:
            self[key]
        except KeyError:
            super(DictList, self).__setitem__(key, [])
        self[key].append(value)


class ServiceGrades(object):

    def __init__(self, course_id):
        self.course_key = CourseKey.from_string(course_id)
        self.course = courses.get_course_by_id(self.course_key)
        self.students = CourseEnrollment.objects.users_enrolled_in(self.course_key)
        self.headers = ['username', 'fullname']

    def get_grades(self):
        course_grades = []
        result = []
        counter_assignment_type = {}

        for student in self.students:
            course_grade_factory = CourseGradeFactory().create(student, self.course)
            gradeset = course_grade_factory.summary
            gradeset["username"] = course_grade_factory.user
            course_grades.append(gradeset)

            sections = course_grade_factory.chapter_grades
            course_data = CourseData(student, course=self.course)
            course_policy = course_data.course.grading_policy

            for grade in course_grades:
                section_grade = DictList()
                sequentials = DictList()
                for student_grade in grade['section_breakdown']:
                    # In graders constructor, we added some additional keys
                    # in the section_breakdown json with the purpose to get the
                    # subsection's parent and be able to differentiate when a grade is
                    # calculated in a single entry. We apply this logic only if
                    # has a subsection object and discard the droppables.
                    if (student_grade.has_key('subsection') and
                        student_grade['subsection'] is not None or
                        student_grade.has_key('only') and not
                        student_grade.has_key('mark')):

                        # Get the parent of each sequential.
                        locator = student_grade['subsection'].location
                        parent = modulestore().get_parent_location(locator)
                        parent_location = modulestore().get_item(parent)

                        assignment_type = student_grade['subsection'].format
                        chapter_name = parent_location.display_name
                        # chapter_name = parent_location
                        
                        for policy in course_policy['GRADER']:
                            counter_assignment_type[assignment_type] = {
                                'total_number': policy['min_count'],
                                'drop': policy['drop_count'],
                                'weight': policy['weight']
                            }
                            if policy['type'] == assignment_type:
                                grade = student_grade['percent'] * policy['weight']                                
                                student_grade.update({'grade': grade})
                                student_grade.update({'chapter_name': chapter_name})
                                sequentials[chapter_name] = student_grade['subsection']

                                # We group in a list the values that has the same keys using DictList
                                # and discard the droppables.
                                if not student_grade.has_key('mark'):
                                    section_grade[chapter_name] = {assignment_type: grade}
                                else:
                                    section_grade[chapter_name] = {assignment_type: 0.0}

            # section_grade.update({'username': student})
            result.append(section_grade)

        return result, counter_assignment_type, sequentials

    def by_section(self, chapter=None):
        course_grade = self.get_grades()
        section_grades = course_grade[0]
        course_policy = course_grade[1]
        score_by_section = []
        counter_assignment_type = {}
        chapter_names = []

        if chapter is not None:
            self.headers.append('Up to date grade')
            course_structure = CourseStructure.objects.get(course_id=self.course_key)
            decoded_structure = json.loads(course_structure.structure_json)
            location = CourseOverview.objects.get(id=self.course_key)
            chapters_course = decoded_structure['blocks'][location.location.to_deprecated_string()]['children']

            index = chapters_course.index(chapter)+1

        for grades in section_grades:
            hasta_aqui = grades.keys()[index]
            for key, value in grades.items():
                self.headers.append(key)
            
            proccessed_section_grade = proccess_grades_dict(grades, course_policy)
            sum_up_to_date = sum(proccessed_section_grade.values()[:index])
            proccessed_section_grade.update({'Up to date grade': sum_up_to_date})
            score_by_section.append(proccessed_section_grade)

        header_rows = proccess_headers(self.headers)
        self.build_csv('section_report.csv', header_rows, score_by_section)
        return score_by_section

    def by_assignment_type(self):
        course_grade = self.get_grades()
        assignment_type_grades = []
        section_grades = course_grade[0]
        course_policy = course_grade[1]
        subsections = course_grade[2]
        

        for student in section_grades:
            total_section = proccess_grades_dict(student, course_policy)
            user = student['username']
            student.update({'username': user.username})
            assignment_type_dict = DictList()
            course_grade_factory = CourseGradeFactory().create(user, self.course)
            for chapter, sequentials in subsections.items():
                for sequential in sequentials:
                    key = '{} - {}'.format(chapter, sequential.format)
                    self.headers.append(chapter)
                    self.headers.append(key)
                    assignment_type_dict[sequential.format] = course_grade_factory.score_for_module(sequential.location)[0]

            # Since we have a list of grades in a key when a chapter has more than two subsequentials
            # with the same assignment type, we need to sum these values and update the dict.
            for key, value in assignment_type_dict.items():
                if isinstance(value, (list,)):
                    total = sum(value)
                    assignment_type_dict.update({key: total})
            assignment_type_dict['username'] = user.username
            assignment_type_grades.append(assignment_type_dict)
        
        # Merge two list of dicts: Array of section grades using by_section method
        # and array of assignment type grades.
        for assignment_type in assignment_type_grades:
            for section in section_grades:
                if assignment_type['username'][0] == section['username']:
                    # Using by_section object bring us general_grade key
                    # we need to delete it since is not neccesary in this report.
                    assignment_type.update(section)

        # headers = proccess_headers(self.headers)
        # self.build_csv('assignment_type_report.csv', headers, assignment_type_grades)
        return assignment_type_grades

    def enhanced_problem_grade(self):
        course_grade = self.get_grades()
        headers = []
        rows = []
        grading_context = grading_context_for_course(self.course_key)

        for student in course_grade:
            course_grade_factory = CourseGradeFactory().create(student["username"], self.course)
            sections = course_grade_factory.chapter_grades
            problem_score_dict = {}
            problem_score_dict['username'] = student['username'].username
            problem_score_dict['fullname'] = student['username'].get_full_name()

            for section in sections.items():
                chapter_name = section[1]['display_name']
                sequentials = section[1]['sections']

                for sequential in sequentials:
                    for problem_score in sequential.problem_scores:
                        for problem_name in grading_context['all_graded_blocks']:
                            if problem_name.fields['category'] == 'problem':
                                if problem_name.location.block_id == problem_score.name:
                                    grade_tuple = course_grade_factory.score_for_module(problem_name.location)
                                    header_name = '{} - {} - {}'.format(chapter_name, sequential.display_name, problem_name.fields['display_name'])
                                    new_header = [header_name + " (Earned)", header_name + " (Possible)"]
                                    problem_score_dict[new_header[0]] = grade_tuple[0]
                                    problem_score_dict[new_header[1]] = grade_tuple[1]
                                    headers.append(new_header)

            rows.append(problem_score_dict)

        flatten_headers = [item for sublist in headers for item in sublist if sublist]
        headers = ['username', 'fullname'] + flatten_headers
        headers = proccess_headers(headers)

        self.build_csv('problem_grade_report.csv', headers, rows)
        return rows

    def build_csv(self, csv_name, header_rows, rows):
        """
        Construct the csv file.

        Arguments:
            csv_name: String for filename
            header_rows: List of values. e.g. ['username', 'section_name']
            rows : List of dicts. e.g [{'username': 'jhon', 'section_name': 'Introduction'}]

            Note that keys in rows argument must have the same names of the header_rows values.
        """

        # Proccess filename
        now = datetime.now(UTC)
        proccesed_date = now.strftime("%Y-%m-%d-%H%M")
        filename = "{}_{}_{}.csv".format(self.course_key, csv_name, proccesed_date)

        csv_file = open(filename, 'w')

        with csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=header_rows)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)

        return csv_file


def proccess_headers(headers):
    """
    Proccess duplicated values in header rows preserving the order.
    """
    seen = set()
    seen_add = seen.add
    return [item for item in headers if not (item in seen or seen_add(item))]


def proccess_grades_dict(grades_dict, counter_assignment_type):
    for section, assignment_types in grades_dict.items():
        if isinstance(assignment_types, (list,)):
            group_grades = []
            for assignment_type in assignment_types:
                for name, grade in assignment_type.items():
                    total_number = counter_assignment_type[name]['total_number']
                    drop = counter_assignment_type[name]['drop']
                    average = grade / (total_number - drop)
                    group_grades.append(average)
            grades_dict.update({section: sum(group_grades)})

    return grades_dict


def calculate_date_grade(self):
    pass
