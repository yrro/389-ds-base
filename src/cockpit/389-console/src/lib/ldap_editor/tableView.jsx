import React from 'react';
import {
  Pagination,
  Spinner,
  Text,
  TextContent,
  TextVariants,
} from '@patternfly/react-core';
import {
  Table, TableHeader, TableBody, TableVariant
} from '@patternfly/react-table';

class EditorTableView extends React.Component {
    constructor (props) {
        super(props);
        this.state = {
        };
    }

    render () {
        const {
            editorTableRows, columns, instanceList,
            loading
        } = this.props;

        let body =
            <div className="ds-margin-top-xlg ds-center">
                <TextContent>
                    <Text component={TextVariants.h3}>
                        Loading ...
                    </Text>
                </TextContent>
                <Spinner className="ds-margin-top-lg" size="lg" />
            </div>;
        if (!loading) {
            body =
                <div>
                   <Table
                       variant={TableVariant.compact}
                       onCollapse={this.props.onCollapse}
                       rows={editorTableRows}
                       cells={columns}
                       actionResolver={this.props.actionResolver}
                       aria-label="editor table view"
                       header={this.props.header ? this.props.header : ""}
                   >
                       <TableHeader />
                       <TableBody />
                   </Table>
                   <Pagination
                       id="ds-addons-editor-view-top"
                       className="ds-margin-top"
                       widgetId="pagination-options-menu-top"
                       itemCount={this.props.itemCount}
                       page={this.props.page}
                       perPage={this.props.perPage}
                       onSetPage={(_evt, value) => this.props.onSetPage(value)}
                       onPerPageSelect={(_evt, value) => this.props.onPerPageSelect(value)}
                   />
               </div>;
        }

        return (
            <div className="ds-indent-lg ds-margin-top-lg">
                {body}
            </div>
        );
    }
}

export default EditorTableView;
