import { Component, type ErrorInfo, type ReactNode } from 'react';
import { Button, Container, Stack, Text, Title } from '@mantine/core';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(): State {
    return { hasError: true };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    console.error('ErrorBoundary caught:', error, errorInfo);
  }

  render(): ReactNode {
    if (this.state.hasError) {
      return (
        <Container size="sm" py="xl">
          <Stack align="center" gap="md">
            <Title order={2}>Something went wrong</Title>
            <Text c="dimmed">
              An unexpected error occurred. Please reload the page to continue.
            </Text>
            <Button onClick={() => window.location.reload()}>
              Reload Page
            </Button>
          </Stack>
        </Container>
      );
    }
    return this.props.children;
  }
}
