// -*- mode: java; c-basic-offset: 2; -*-
// Copyright 2009-2011 Google, All Rights reserved
// Copyright 2011-2012 MIT, All rights reserved
// Released under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

package com.google.appinventor.client.explorer.youngandroid;

import com.google.appinventor.client.ErrorReporter;
import com.google.appinventor.client.Ode;
import com.google.appinventor.client.OdeAsyncCallback;
import com.google.appinventor.client.boxes.ProjectListBox;
import com.google.appinventor.client.boxes.ViewerBox;
import com.google.appinventor.client.explorer.project.Project;
import com.google.appinventor.client.tracking.Tracking;
import com.google.appinventor.client.widgets.Toolbar;
import com.google.appinventor.client.wizards.youngandroid.NewYoungAndroidProjectWizard;
import com.google.gwt.user.client.Command;
import com.google.gwt.user.client.Window;

import java.util.List;

import static com.google.appinventor.client.Ode.MESSAGES;

/**
 * The project toolbar houses command buttons in the Young Android Project tab.
 *
 */
public class ProjectToolbar extends Toolbar {
  private static final String WIDGET_NAME_NEW = "New";
  private static final String WIDGET_NAME_DELETE = "Delete";

  private boolean isReadOnly;

  /**
   * Initializes and assembles all commands into buttons in the toolbar.
   */
  public ProjectToolbar() {
    super();
    isReadOnly = Ode.getInstance().isReadOnly();

    addButton(new ToolbarItem(WIDGET_NAME_NEW, MESSAGES.newProjectMenuItem(),
        new NewAction(this)));

    addButton(new ToolbarItem(WIDGET_NAME_DELETE, MESSAGES.deleteProjectButton(),
        new DeleteAction()));

    updateButtons();
  }

  private static class NewAction implements Command {
    ProjectToolbar parent;

    public NewAction(ProjectToolbar parent) {
      this.parent = parent;
    }

    @Override
    public void execute() {
      if (Ode.getInstance().screensLocked()) {
        return;                 // Refuse to switch if locked (save file happening)
      }
      // Disabled the Start New Project button. We do this because on slow machines people
      // click it multiple times while the wizard (below) is starting. This then causes
      // a second wizard to start and a very confused user experience.
      // We will enable the button again when we re-visit the Project List page
      parent.setButtonEnabled(WIDGET_NAME_NEW, false);
      new NewYoungAndroidProjectWizard(parent).center();
      // The wizard will switch to the design view when the new
      // project is created.
    }
  }

  private static class DeleteAction implements Command {
    @Override
    public void execute() {
      Ode.getInstance().getEditorManager().saveDirtyEditors(new Command() {
        @Override
        public void execute() {
          List<Project> selectedProjects =
              ProjectListBox.getProjectListBox().getProjectList().getSelectedProjects();
          if (selectedProjects.size() > 0) {
            // Show one confirmation window for selected projects.
            if (deleteConfirmation(selectedProjects)) {
              for (Project project : selectedProjects) {
                deleteProject(project);
              }
            }
          } else {
            // The user can select a project to resolve the
            // error.
            ErrorReporter.reportInfo(MESSAGES.noProjectSelectedForDelete());
          }
        }
      });
    }

    private boolean deleteConfirmation(List<Project> projects) {
      String message;
      if (projects.size() == 1) {
        message = MESSAGES.confirmDeleteSingleProject(projects.get(0).getProjectName());
      } else {
        StringBuilder sb = new StringBuilder();
        String separator = "";
        for (Project project : projects) {
          sb.append(separator).append(project.getProjectName());
          separator = ", ";
        }
        String projectNames = sb.toString();
        message = MESSAGES.confirmDeleteManyProjects(projectNames);
      }
      return Window.confirm(message);
    }

    private void deleteProject(Project project) {
      Tracking.trackEvent(Tracking.PROJECT_EVENT,
          Tracking.PROJECT_ACTION_DELETE_PROJECT_YA, project.getProjectName());

      final long projectId = project.getProjectId();

      Ode ode = Ode.getInstance();
      boolean isCurrentProject = (projectId == ode.getCurrentYoungAndroidProjectId());
      ode.getEditorManager().closeProjectEditor(projectId);
      if (isCurrentProject) {
        // If we're deleting the project that is currently open in the Designer we
        // need to clear the ViewerBox first.
        ViewerBox.getViewerBox().clear();
      }
      // Make sure that we delete projects even if they are not open.
      doDeleteProject(projectId);
    }

    private void doDeleteProject(final long projectId) {
      Ode.getInstance().getProjectService().deleteProject(projectId,
          new OdeAsyncCallback<Void>(
              // failure message
              MESSAGES.deleteProjectError()) {
        @Override
        public void onSuccess(Void result) {
          Ode.getInstance().getProjectManager().removeProject(projectId);
          // Show a welcome dialog in case there are no
          // projects saved.
          if (Ode.getInstance().getProjectManager().getProjects().size() == 0) {
            Ode.getInstance().createNoProjectsDialog(true);
          }
        }
      });
    }

  }

  /**
   * Enables and/or disables buttons based on how many projects exist
   * (in the case of "Download All Projects") or are selected (in the case
   * of "Delete" and "Download Source").
   */
  public void updateButtons() {
    ProjectList projectList = ProjectListBox.getProjectListBox().getProjectList();
    int numProjects = projectList.getNumProjects();
    int numSelectedProjects = projectList.getNumSelectedProjects();
    if (isReadOnly) {           // If we are read-only, we disable all buttons
      setButtonText(WIDGET_NAME_PUBLISH_OR_UPDATE, MESSAGES.publishToGalleryButton());
      setButtonEnabled(WIDGET_NAME_NEW, false);
      setButtonEnabled(WIDGET_NAME_DELETE, false);
      setButtonEnabled(WIDGET_NAME_PUBLISH_OR_UPDATE, false);
      Ode.getInstance().getTopToolbar().fileDropDown.setItemEnabled(MESSAGES.exportProjectMenuItem(),
        numSelectedProjects > 0);
      Ode.getInstance().getTopToolbar().fileDropDown.setItemEnabled(MESSAGES.exportAllProjectsMenuItem(),
        numSelectedProjects > 0);
      return;
    }
    setButtonEnabled(WIDGET_NAME_DELETE, numSelectedProjects > 0);
    Ode.getInstance().getTopToolbar().fileDropDown.setItemEnabled(MESSAGES.deleteProjectMenuItem(),
        numSelectedProjects > 0);
    Ode.getInstance().getTopToolbar().fileDropDown.setItemEnabled(MESSAGES.exportProjectMenuItem(),
        numSelectedProjects > 0);
    Ode.getInstance().getTopToolbar().fileDropDown.setItemEnabled(MESSAGES.exportAllProjectsMenuItem(),
        numSelectedProjects > 0);
  }

  // If we started a project, then the start button was disabled (to avoid
  // a second press while the new project wizard was starting (aka we "debounce"
  // the button). When the person switches to the projects list view again (here)
  // we re-enable it.
  public void enableStartButton() {
    if (!isReadOnly) {
      setButtonEnabled(WIDGET_NAME_NEW, true);
    }
  }

}
